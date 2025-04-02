use env_logger::Builder;
use std::fs::File;
use std::io::Write;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_logging() {
    INIT.call_once(|| {
        let log_path = "logs/debug.log";
        if std::path::Path::new(log_path).exists() {
            let _ = std::fs::remove_file(log_path);
        }
        let _ = std::fs::create_dir_all("logs");

        match File::create(log_path) {
            Ok(file) => {
                let _ = Builder::new()
                    .format_timestamp_secs()
                    .format(|buf, record| {
                        writeln!(
                            buf,
                            "[{} {:<5}] {}",
                            buf.timestamp(),
                            record.level(),
                            record.args()
                        )
                    })
                    .filter_level(log::LevelFilter::Debug)
                    .write_style(env_logger::WriteStyle::Always)
                    .target(env_logger::Target::Pipe(Box::new(file)))
                    .try_init();
            }
            Err(e) => eprintln!("Failed to initialize logging: {}", e),
        }
    });
}
