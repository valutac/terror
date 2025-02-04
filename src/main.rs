use aws_config::meta::region::RegionProviderChain;
use chrono::Utc;
use clap::{command, Parser, Subcommand};
use glob::glob;
use std::{fs::{self, File}, io::{self, Write}, path::Path, process::{exit, Command}};
use std::io::Error;
use tar::Builder;

#[derive(Parser)]
#[command(name = "Terror")]
#[command(about = "Night Terror")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    MongoDump {
        #[arg(long)]
        backup_dir: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        auth_db: String,
        #[arg(long)]
        db_name: String,
        #[arg(long, default_value_t = false)]
        upload: bool,
        #[arg(long, default_value_t = String::from("backup"))]
        upload_dir: String,
        #[arg(long, default_value_t = String::from("default"))]
        s3_profile: String,
        #[arg(long, default_value_t = String::from("backup"))]
        bucket: String,
    },
    S3Setup {
        #[arg(long)]
        access_key: String,
        #[arg(long)]
        secret_key: String,
        #[arg(long)]
        region: String,
    }
}

fn count_matching_dirs(pattern: &str) -> Result<usize, Error> {
    let mut count = 0;

    // Use glob to match directories based on the given pattern
    for entry in glob(pattern).unwrap() {
        match entry {
            Ok(path) if path.is_file() => count += 1, // Increment the count for directories
            _ => {} // Ignore non-directories or errors
        }
    }

    Ok(count)
}

fn run_mongodump(username: &str, password: &str, auth_db: &str, db_name: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Prepare the mongodump command
    let output = Command::new("mongodump")
        .arg("--gzip")
        .arg("-u")
        .arg(username)
        .arg(format!("-p{}", password))
        .arg("--authenticationDatabase")
        .arg(auth_db)
        .arg("--db")
        .arg(db_name)
        .arg("--out")
        .arg(output_path)
        .output();

    match output {
        Ok(output) => {
            if !output.status.success() {
                eprintln!("mongodump failed with error: {}", String::from_utf8_lossy(&output.stderr));
                exit(1); // Exit with error code
            } else {
                println!("Database dump completed successfully!");
                println!("Dump saved to: {}", output_path);
            }
        }
        Err(err) => {
            eprintln!("Error executing mongodump: {}", err);
            exit(1); // Exit with error code
        }
    }

    Ok(())
}

fn add_to_tar<W: Write>(builder: &mut Builder<W>, path: &Path, base_path: &Path) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            add_to_tar(builder, &entry_path, base_path)?;
        }
    } else if path.is_file() {
        let relative_path = path.strip_prefix(base_path).unwrap();
        // let mut file = File::open(path)?;
        builder.append_path_with_name(path, relative_path)?;
    }
    Ok(())
}

fn create_tar_gz_archive(dir_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tar_file = File::create(output_path)?;
    let mut builder = Builder::new(tar_file);
    let src_path = Path::new(dir_path);
    
    add_to_tar(&mut builder, src_path, src_path)?;
    
    builder.finish()?;
    Ok(())
}

async fn upload_to_s3(s3_profile: &str, bucket: &str, file_path: &str, s3_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Load AWS credentials and region from environment
    let region_provider = RegionProviderChain::default_provider().or_else("ap-southeast-3");
    let shared_config = aws_config::from_env()
        .region(region_provider)
        .profile_name(s3_profile)
        .load()
        .await;
    // let config = aws_config::load_from_env().await;
    let client = aws_sdk_s3::Client::new(&shared_config);

    if let Ok(_) = client.head_object().bucket(bucket).key(s3_key).send().await {
        println!("File '{}' already exists in the S3 bucket '{}'. Skipping upload.", s3_key, bucket);
        return Ok(());
    }

    let body = aws_sdk_s3::primitives::ByteStream::from_path(std::path::Path::new(file_path)).await;

    client
        .put_object()
        .bucket(bucket)
        .key(s3_key)
        .body(body.unwrap())
        .send()
        .await?;

    println!("File uploaded to S3: {}/{}", bucket, s3_key);
    Ok(())
}

async fn mongo_dump(username: &str, password: &str, auth_db: &str, db_name: &str, backup_root: &str, upload: bool, upload_dir: &str, s3_profile: &str, bucket: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Count the number of directories in the backup directory
    let now = Utc::now();
    let mut backup_dir = format!("{}/{}_*", backup_root, now.format("%Y-%m-%d"));
    let total = match count_matching_dirs(&backup_dir) {
        Ok(count) => count,
        Err(e) => {
            eprintln!("Error counting directories: {}", e);
            0
        }
    };

    println!("Backup count {}: {}", backup_dir, total);
    backup_dir = format!("{}/{}_{}", backup_root, now.format("%Y-%m-%d"), total + 1);
    println!("Final backup dir {}", backup_dir);
    fs::create_dir_all(&backup_dir)?;

    // create dump
    run_mongodump(username, password, auth_db, db_name, &backup_dir)?;

    // create targz
    let output_path = format!("{}.tar.gz", &backup_dir);
    create_tar_gz_archive(&backup_dir, &output_path)?;

    // delete backup_dir
    fs::remove_dir_all(backup_dir)?;

    // upload to s3
    if upload {
        let s3_key = format!("{}/{}", upload_dir, output_path.split("/").last().unwrap());
        upload_to_s3(s3_profile, bucket, &output_path, &s3_key).await?;
    }

    Ok(())
}

fn setup_s3(access_key: &str, secret_key: &str, region: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(format!("{}/.aws", std::env::var("HOME").unwrap()))?;

    // Write .aws credentials file
    let credentials = format!("[default]\naws_access_key_id = {}\naws_secret_access_key = {}", access_key, secret_key);
    let credentials_path = format!("{}/.aws/credentials", std::env::var("HOME").unwrap());
    fs::write(credentials_path, credentials)?;

    // Write .aws config file
    let config = format!("[default]\nregion = {}", region);
    let config_path = format!("{}/.aws/config", std::env::var("HOME").unwrap());
    fs::write(config_path, config)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::MongoDump { backup_dir, username, password, auth_db, db_name, upload, upload_dir, s3_profile, bucket } => {
            mongo_dump(&username, &password, &auth_db, &db_name, &backup_dir, upload, &upload_dir, &s3_profile, &bucket).await?;
        },
        Commands::S3Setup { access_key, secret_key, region } => {
            setup_s3(&access_key, &secret_key, &region)?;
        },
    }

    Ok(())
}
