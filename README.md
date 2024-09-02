[![Rust 1.80](https://img.shields.io/badge/rust-1.80+-red.svg)](https://www.rust-lang.org/tools/install)
[![Lint Build Release](https://github.com/plasticuproject/dashboard_datatable_builder/actions/workflows/rust.yml/badge.svg)](https://github.com/plasticuproject/dashboard_datatable_builder/actions/workflows/rust.yml)
![Maintenance](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)

# Dashboard DataTable Builder

The `dashboard_datatable_builder` is a Rust-based tool designed to process large volumes of CSV log data, specifically targeting structured log files with threat indicators, priorities, and other critical information. It extracts, cleans, consolidates, and sorts data into a succinct CSV format, facilitating the generation of data tables for dashboard integrations or further analysis.

## Features

- **Pattern-based File Selection**: Chooses log files for processing based on their names and modification dates, focusing on recent data.
- **Data Cleaning and Deduplication**: Utilizes regular expressions to clean 'Event Description' fields and ensures that only unique data entries are included in the output.
- **Date Filtering**: Filters log entries to include only those within a specified range of recent days, allowing for targeted analysis. Entries are first filtered by user-specified days and then by a default retention period of 15 days.
- **Condition-based Filtering**: Further filters entries to include only those that are flagged as 'Blocked' in the dataset.
- **Efficient Data Handling**: Processes files in a memory-efficient manner, suitable for handling large datasets without overwhelming system resources.
- **Sorted CSV Output**: Produces an `events.csv` file that combines filtered, cleaned, and sorted (by date) entries for easy use in data tables or dashboards.

## Getting Started

### Prerequisites

- Rust 1.8.0 or later
- Cargo for managing Rust packages

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/plasticuproject/dashboard_datatable_builder.git
   ```

2. Navigate to the project directory:

   ```sh
   cd dashboard_datatable_builder
   ```

3. Build the project:

   ```sh
   cargo build --release
   ```

### Usage

Ensure your designated directory (e.g., `/var/log/fwd/db/`) is populated with compatible log files.
To run the aggregator, provide the path to your log files directory and the number of days back to filter the files based on their modification date as arguments:

   ```sh
   cargo run --release <path_to_log_files> <days_back>
   ```

For example, to process logs from the last 15 days in the `/var/log/fwd/db` directory:

   ```sh
   cargo run --release /var/log/fwd/db 15
   ```

You can also execute the pre-built binary in the directory where you want your output files to reside:

   ```sh
   ./dashboard_datatable_builder /var/log/fwd/db 15
   ```

The program will generate an `events.csv` file in the current working directory, containing the processed, aggregated, and sorted data.

### Post-Execution

After running the program, check the `events.csv` file for your aggregated data. This file is overwritten each time the program is run to ensure it contains only the most recent and relevant entries.

### Note

The default retention period for the final filtering step is set to 15 days. This means after initial processing based on the `days_back` parameter, entries older than 7 days from the current date are further filtered out before the final write operation.
