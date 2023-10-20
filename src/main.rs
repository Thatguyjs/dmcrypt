mod decrypt;

use clap::{Arg, crate_authors, crate_version, crate_name, ArgAction};
use std::{fs, path::{PathBuf, Path}, ffi::OsStr, error::Error};


// Collect a list of all *.dm (LG encrypted) files
fn find_files<P: AsRef<Path>>(paths: Vec<P>, recurse: bool) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = paths.iter().map(|p| PathBuf::from(p.as_ref())).collect();
    let mut files = vec![];

    while let Some(path) = paths.pop() {
        if !path.exists() {
            println!("Info: The input path \"{}\" does not exist", path.display());
            continue;
        }

        if path.is_dir() {
            paths.append(&mut path.read_dir()
                .expect("Failed to read directory")
                .map(|e| e.expect("Failed to get directory entry").path())
                .filter(|p| recurse || !p.is_dir())
                .collect());
        }
        else if path.extension() == Some(OsStr::new("dm")) {
            files.push(path);
        }
    }

    files
}


// Read an encrypted file, extract & generate decryption info, and decrypt the file body
fn decrypt_file(path: &PathBuf, email: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let data = fs::read(path)?;

    let (flock, iv, body) = decrypt::extract_header(&data)?;
    let key = decrypt::generate_key(email, flock);

    Ok(decrypt::decrypt_data(&key, iv, body)?)
}


fn main() {
    let app = clap::Command::new(crate_name!())
        .author(crate_authors!())
        .version(crate_version!())
        .args([
            Arg::new("email").required(true)
                .help("The email address used to encrypt the file (most likely the account signed in on your device)"),
            Arg::new("input").action(ArgAction::Append).required(true)
                .help("Input file or directory"),
            Arg::new("output").long("output").short('o').required(true)
                .help("Output file or directory"),
            Arg::new("recurse").long("recurse").short('r').action(ArgAction::SetTrue)
                .help("If <input> is a directory, decrypt all files including sub-directories")
        ])
        .get_matches();

    let email = app.get_one::<String>("email").unwrap();
    let inputs: Vec<&str> = app.get_many::<String>("input").unwrap_or_default().map(|i| i.as_str()).collect();
    let inputs = find_files(inputs, app.get_flag("recurse"));
    let output = PathBuf::from(app.get_one::<String>("output").unwrap());

    for path in inputs {
        match decrypt_file(&path, &email) {
            Ok(data) => {
                let out_path = output.join(path.with_extension(""));
                let out_dir = out_path.parent().unwrap_or(Path::new("."));

                if let Err(e) = fs::create_dir_all(out_dir) {
                    eprintln!("Error: Could not create output directory: {e}");
                    eprintln!("Skipping file: \"{}\"", out_path.display());
                }
                else if let Err(e) = fs::write(&out_path, data) {
                    eprintln!("Error: Failed to create \"{}\": {e}", out_path.display());
                }
                else {
                    println!("\"{}\" -> \"{}\"", path.display(), out_path.display());
                }
            },

            Err(e) => eprintln!("Error: \"{}\": {}", path.display(), e)
        }
    }

    println!("Done!");
}
