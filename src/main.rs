use chrono::{Duration, Local, NaiveDateTime};
use csv::{ReaderBuilder, Trim, WriterBuilder};
use regex::Regex;
use std::collections::HashSet;
use std::convert::TryInto;
use std::env;
use std::fs::{self, DirEntry, File, OpenOptions};
use std::io::{self, BufReader, BufWriter};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Filters files in a specified directory that match a naming pattern and were modified
/// within a specified number of days back from the current date.
///
/// This function looks for files starting with "fwddmp.log.tmp" and filters them based on their
/// last modified time, keeping only those modified within the last `days_back` days.
///
/// # Arguments
/// - `path`: A reference to the path of the directory to search in.
/// - `days_back`: The number of days back from the current date to consider when filtering files.
///                Files modified more recently than this will be included in the results.
///
/// # Returns
/// A vector of `DirEntry` representing the filtered files that match the criteria.
///
/// # Panics
/// Panics if reading the directory fails, if there is an error calculating time durations,
/// or if converting system times to a comparable format fails.
fn filter_files(path: &Path, days_back: i64) -> Vec<DirEntry> {
    let now = Local::now();
    fs::read_dir(path)
        .expect("Error reading directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("fwddmp.log.tmp")
                && entry
                    .metadata()
                    .map(|meta| {
                        let file_time = meta
                            .modified()
                            .unwrap_or_else(|_| SystemTime::now())
                            .duration_since(UNIX_EPOCH)
                            .expect("Error calculating time duration")
                            .as_secs();

                        // Safely convert chrono::DateTime to u64 for comparison
                        let comparison_time = (now
                            - Duration::try_days(days_back).expect("Valid duration"))
                        .timestamp()
                        .try_into()
                        .expect("Timestamp conversion error");

                        file_time > comparison_time
                    })
                    .unwrap_or(false)
        })
        .collect()
}

/// Static global regex pattern used for cleaning event descriptions.
/// This pattern matches any leading characters that start with `[`,
/// followed by any characters until `>`, including the `>` and any trailing whitespace.
static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();

/// Cleans an event description by removing specific patterns defined in the REGEX.
///
/// The function uses a precompiled regex that matches and removes metadata or formatting
/// prefixes typically found at the start of log messages. This regex is compiled once and reused
/// across function calls.
///
/// # Arguments
/// * `event_description` - A string slice that holds the event description text to be cleaned.
///
/// # Returns
/// Returns a new `String` with the specified patterns removed from the beginning of the `event_description`.
///
/// # Panics
/// Panics if the regex pattern compilation fails. This should only occur if the pattern is invalid.
fn clean_event_description(event_description: &str) -> String {
    let regex = REGEX.get_or_init(|| Regex::new(r"^\[.*?>\s*").expect("Invalid regex"));
    regex.replace_all(event_description, "").to_string()
}

/// Processes a CSV file to extract and clean data entries based on a specified date range.
///
/// This function reads a CSV file without headers, trimming all fields. It filters the records
/// based on the 'Date/Time' field to include only those within the specified number of days back
/// from the current date. Additionally, it checks that the event 'Blocked' status is set to '1',
/// indicating the 'Source IP Address' has been blocked. For each qualifying record, it constructs a
/// string that combines several fields: 'Date/Time', 'Source IP Address', 'Destination IP Address',
/// a cleaned 'Event Description', and 'Priority'. Each unique combination is added to a `HashSet`
/// to ensure no duplicates.
///
/// # Arguments
/// * `file_path` - A reference to the path of the CSV file to be processed.
/// * `days_back` - The number of days back from the current date to filter records by their
///   'Date/Time' field. Only records with a 'Date/Time' on or after this threshold are included.
///
/// # Returns
/// A `Result` wrapping a `HashSet<String>` containing the unique, cleaned entries from the file.
/// Each entry in the `HashSet` is a comma-separated string with the format:
/// "Date/Time,Source IP,Destination IP,Event Description,Priority"
///
/// The 'Event Description' field is cleaned to remove specific patterns using a regular expression,
/// which typically involves stripping metadata or formatting prefixes.
///
/// # Errors
/// Returns an `io::Error` if reading the file fails at any point, including issues with opening the file,
/// reading its contents, or parsing individual records.
///
/// # Panics
/// This function can panic if parsing the 'Date/Time' strings to `NaiveDateTime` fails for any line that
/// is attempted to be included based on the `days_back` criteria. It can also panic if the regex used
/// for cleaning 'Event Description' fields fails to compile or apply, although this is unlikely with a
/// correctly specified regex pattern.
fn process_csv_file(file_path: &Path, days_back: i64) -> io::Result<HashSet<String>> {
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .trim(Trim::All)
        .from_path(file_path)?;
    let mut unique_entries = HashSet::new();
    let now = Local::now();
    let cutoff = now - Duration::days(days_back);

    for result in rdr.records() {
        let record = match result {
            Ok(record) => record,
            Err(e) => {
                println!("Failed to read record: {e}");
                continue;
            }
        };
        let date_time_str = record.get(4).unwrap_or_default();
        if let Ok(date_time) = NaiveDateTime::parse_from_str(date_time_str, "%Y/%m/%d %H:%M:%S") {
            if date_time > cutoff.naive_local() && record.get(11).unwrap_or_default() == "1" {
                let source_ip = record.get(6).unwrap_or_default();
                let destination_ip = record.get(12).unwrap_or_default();
                let event_description = record.get(3).unwrap_or_default();
                let cleaned_description = clean_event_description(event_description);
                let priority = record.get(1).unwrap_or_default();

                let entry = format!(
                    "{date_time_str},{source_ip},{destination_ip},{cleaned_description},{priority}"
                );
                unique_entries.insert(entry);
            }
        } else {
            println!("Skipping record with invalid date: {date_time_str}");
            continue;
        }
    }

    Ok(unique_entries)
}

/// Appends a set of string entries to a CSV file at the specified path.
///
/// This function takes a `HashSet` of string entries, each expected to be a
/// comma-separated value (CSV) string, and appends them to a CSV file. The order of the entries
/// in the output file is not guaranteed due to the nature of `HashSet`. The function creates
/// the file if it does not exist and appends to it if it does.
///
/// # Arguments
/// * `entries` - A `HashSet<String>` containing the CSV-formatted entries to be appended to the file.
///   Each string in the set should be a single CSV record.
/// * `output_path` - A reference to the path where the output CSV file will be written. If a file
///   at this path already exists, the entries will be appended to it. If it does not exist, a new file
///   will be created.
///
/// # Returns
/// An `io::Result<()>` indicating the success of the operation. Returns `Ok(())` if the append
/// operation completes successfully.
///
/// # Errors
/// Returns an `io::Error` if the file cannot be created or appended to. This includes errors related
/// to file permissions, disk space, or other I/O errors.
fn write_to_csv(entries: HashSet<String>, output_path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(output_path)?;

    let mut wtr = WriterBuilder::new().from_writer(file);

    for entry in entries {
        wtr.write_record(entry.split(','))?;
    }

    wtr.flush()?;
    Ok(())
}

/// Filters and sorts entries in a CSV file based on a date threshold and removes duplicates.
///
/// This function reads entries from a CSV file, filters out entries older than a specified number of days,
/// removes any duplicates, sorts the remaining entries in descending order by date, and then writes the
/// processed entries back to the same file, overwriting the original content.
///
/// # Arguments
/// * `input_path` - A reference to the path of the CSV file to be processed. This file should contain
///   records with a date field as the first value in each record.
/// * `days_back` - The number of days back from the current date to use as a cutoff for filtering records.
///   Records with a date older than this will be excluded from the output.
///
/// # Returns
/// An `io::Result<()>` that indicates the success or failure of the read, write, and file operations.
/// Returns `Ok(())` if the operations complete successfully.
///
/// # Errors
/// Returns an `io::Error` if any issues occur during file opening, reading, or writing. Possible errors
/// include problems with file permissions, the file not existing, or hardware-related I/O errors.
///
/// # Panics
/// This function panics if the date parsing fails, indicating invalid date formats in the input CSV.
fn filter_csv_by_date(input_path: &Path, days_back: i64) -> io::Result<()> {
    let now = Local::now().naive_local(); // Use naive_local to avoid timezone issues
    let cutoff = now - Duration::days(days_back);

    let file = File::open(input_path)?;
    let mut reader = ReaderBuilder::new()
        .trim(Trim::All)
        .from_reader(BufReader::new(file));

    let mut records_to_keep = HashSet::new();

    for result in reader.records() {
        let record = result?;
        if let Some(date_str) = record.get(0) {
            if let Ok(date_time) = NaiveDateTime::parse_from_str(date_str, "%Y/%m/%d %H:%M:%S") {
                if date_time > cutoff {
                    // Convert the record to a string for hashing and comparison
                    let record_str = record.iter().collect::<Vec<&str>>().join(",");
                    records_to_keep.insert(record_str);
                }
            }
        }
    }

    // Convert HashSet to Vec and sort
    let mut sorted_records: Vec<_> = records_to_keep.iter().collect();
    sorted_records.sort_by(|a, b| {
        let a_date = a.split(',').next().unwrap_or_default();
        let b_date = b.split(',').next().unwrap_or_default();
        let a_parsed_date =
            NaiveDateTime::parse_from_str(a_date, "%Y/%m/%d %H:%M:%S").expect("RESULT");
        let b_parsed_date =
            NaiveDateTime::parse_from_str(b_date, "%Y/%m/%d %H:%M:%S").expect("RESULT");
        b_parsed_date.cmp(&a_parsed_date) // Sort in descending order
    });

    // Overwrite the original file with the filtered records
    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(input_path)?;
    let mut writer = WriterBuilder::new().from_writer(BufWriter::new(file));

    // Write each unique and date-valid record back to the CSV
    for record_str in sorted_records {
        writer.write_record(record_str.split(','))?;
    }

    writer.flush()?;

    Ok(())
}

/// Entry point for the CSV data processing application.
///
/// This application processes CSV files from a specified directory, filters the entries based on their
/// modification date to consider only recent data, extracts and cleans data entries, and then writes the
/// unique and sorted entries to a new CSV file named "events.csv". The cleaning process involves removing
/// specified patterns from the 'Event Description' field using a regular expression. Additionally, the
/// entries are initially sorted by the 'Date/Time' field in descending order and filtered to include only entries
/// from the last specified number of days provided by the user. After writing the initial processed data, the
/// entries are further filtered to a default retention period of 15 days before final writing to the output file.
///
/// # Arguments
/// The application accepts two command-line arguments:
/// - `path_to_log_files`: The path to the directory containing the log files.
/// - `days_back`: The number of days back to consider when initially filtering files based on their
///   modification date. Only entries within this user-specified date range are initially considered.
///
/// # Output
/// The output is a CSV file named "events.csv", which will be created or overwritten
/// in the current working directory. This file contains the processed entries without
/// duplicates, initially sorted by the 'Date/Time' field in descending order and filtered
/// by the days specified by the user, and finally by a default retention period of 7 days.
///
/// # Exit Codes
/// The application will exit with one of the following codes:
/// - `0`: The operation completed successfully.
/// - `1`: The operation failed due to incorrect usage (e.g., not enough arguments
///   were provided).
///
/// # Errors
/// The function returns an `io::Result<()>`:
/// - `Ok(())` indicates that the files were processed successfully, and the output
///   file was created or overwritten as expected.
/// - An `Err` value indicates that an I/O error occurred during the operation, such
///   as issues reading the input files, parsing the CSV data, or writing to the
///   output file.
fn main() -> io::Result<()> {
    let retention_days = 15;
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <path_to_log_files> <days_back>", args[0]);
        std::process::exit(1);
    }

    let log_file_path = &args[1];
    let days_back: i64 = args[2].parse().expect("Invalid number of days");

    // Specify the output path directly
    let output_path = Path::new("events.csv");

    let files = filter_files(Path::new(log_file_path), days_back);
    let mut all_entries = HashSet::new();

    for file in files {
        println!("Processing file: {}", file.path().display());
        let entries = process_csv_file(&file.path(), days_back)?;
        all_entries.extend(entries);
    }

    let _ = write_to_csv(all_entries, output_path);
    filter_csv_by_date(output_path, retention_days)
}
