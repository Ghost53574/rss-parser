use std::fs::File;
use std::path::Path;
use std::io::{ BufWriter, Write, Read };
use std::time::{ SystemTime };
use std::hash::{ Hash, Hasher };
use std::collections::hash_map::DefaultHasher;
use std::str;
use tracing::{ info, error, warn };
use tracing_subscriber::EnvFilter;
use select::document::Document;
use select::predicate::{Class, Name, Attr, Predicate};
use feed_rs::{ model, parser };
use clap::{ App, Arg, AppSettings };
use serde_json::Result;
use serde::{ Serialize, Deserialize };
use regex::Regex;

extern crate reqwest;
extern crate select;
extern crate serde_json;

/// Options struct definition
/// version: Current version
/// conf:    Site Configuration
/// max:     Max pages to be scraped / parsed
/// out:     Output file for the initialization database
/// timeout: The default timeout given per iteration of getting URLs
/// limit:   Automatically set if the max is set to 0, means unlimited pages
/// name:    Named title of the Feed
/// desc:    Description of the Feed source
/// next:    The next parameter
/// init:    Automatically set if --config is used instead of --read
#[derive(Default)]
pub struct RssOptions {
    version:      String,
    conf:         String,
    max:          u64,
    out:          String,
    timeout:      u64,
    url:          String,
    limit:        bool,
    name:         String,
    desc:         String,
    next:         String,
    init:         bool
}

/// Config struct definition
/// Uses the same values as in the RssOptions struct but includes the Feed vars
/// tags:     The tags are the element tags that are going to be scrapped
/// sections: These are the class and id attribute names per section
/// elements: These are for the individual elements to be captured in each section
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub struct RssConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    name:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri:          Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next:         Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout:      Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max:          Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags:         Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sections:     Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elements:     Option<Vec<String>>
}

/// Labels struct definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RssLabels {
    Title,
    Date,
    Description,
    Url,
    Misc,
}

/// Element struct definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RssElement {
    label:        RssLabels,
    name:         String,
    value:        String,
}

/// Section struct definition
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RssSection {
    url:          String,
    page:         u64,
    section:      Vec<RssElement>
}

/// Hash struct definition
#[derive(Debug, Hash, Clone)]
#[derive(Serialize, Deserialize)]
pub struct RssHash {
    title:        String,
    desc:         String,
    first:        String
}

/// Feed struct definition
#[derive(Debug, Default, Clone)]
#[derive(Serialize, Deserialize)]
pub struct RssFeed {
    date:         u64,
    hash:         u64,
    config:       RssConfig,
    sections:     Vec<RssSection>
}

/// Config implementation
impl RssConfig {
    pub fn new() -> RssConfig {
        RssConfig {
            ..Default::default()
        }
    }

    /// pub fn ReadConfig(path: String, conf: &Config)
    /// Reads a .conf file that has the configuration for how the DOM will be
    /// parsed. This Config will be returned for continued processing.
    pub fn read_config<P: AsRef<Path>>(path: P) -> std::result::Result<RssConfig, serde_json::Error> {
        let f = File::open(path);
        if Some(&f).is_none() {
            error!("File could not be read!");
            std::process::exit(1);
        }
        else {
            let mut file_config = String::new();
            let _file_read = f.unwrap().read_to_string(&mut file_config);
            serde_json::from_str(&file_config[..])
        }
    }
}

/// Section implementation
impl RssSection {
    pub fn new() -> RssSection {
        RssSection {
            ..Default::default()
        }
    }
}

/// Feed implementation
impl RssFeed {
    pub fn new() -> RssFeed {
        RssFeed {
            ..Default::default()
        }
    }

    /// pub fn read_feed(path: Path<P>)
    /// Reads a .conf file that has the configuration for how the DOM will be parsed
    pub fn read_feed<P: AsRef<Path>>(path: P) -> std::result::Result<RssFeed, serde_json::Error> {
        let f = File::open(path);
        if Some(&f).is_none() {
            error!("File could not be read!");
            std::process::exit(1);
        }
        else {
            let mut file_config = String::new();
            let _file_read = f.unwrap().read_to_string(&mut file_config);
            serde_json::from_str(&file_config[..])
        }
    }

    /// pub fn write_feed(path: Path<P>, rss_feed: &RssFeed)
    /// Writes the RssFeed to a file
    pub fn write_feed<P: AsRef<Path>>(path: P, rss_feed: &RssFeed) -> std::result::Result<(), std::io::Error> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(false)
            .open(path);
        match f {
            Ok(_) => {
                info!("Operation success: Output file created");
            }
            Err(err) => {
                error!("Operation failed: {}", err);
                std::process::exit(1);
            }
        }
        let mut buf_writer = BufWriter::new(f.unwrap());
        match write!(buf_writer, "{}", serde_json::to_string_pretty(&rss_feed).unwrap()) {
            Ok(_) => { Ok(()) },
            Err(e) => { Err(e) }
        }
    }
}

/// pub fn get_items(html: &Document, tags: &Vec<String>, sections: &Vec<String>, elements: &Vec<StrString>)
/// Get items from DOM that are listed in the config
pub fn get_items(html: &Document,
                    tags:     &Vec<String>,
                    sections: &Vec<String>,
                    elements: &Vec<String>,
                    ) -> Vec<RssElement> {
    let mut rss_elemnts: Vec<RssElement> = Vec::new();
    for class in sections {
        for node in html.find(Class(class.as_str())) {
            for tag in tags {
                for attr in elements {
                    let element = node.find(Class(attr.as_str())).next();
                    if element.is_some() {
                        if tag.as_str() == "a" {
                            if element.is_none() {
                                continue
                            }
                            let result_href = element.unwrap().attr("href");
                            if result_href.is_none() {
                                continue
                            }
                            let href = result_href.unwrap().to_string();
                            rss_elemnts.push(RssElement {
                                label: RssLabels::Misc,
                                name: attr.to_string(),
                                value: href
                            });
                        }
                        else {
                            // The Regex::new(r"\s+") will match on two or more
                            // space. So following re.replace_all replaces all
                            // occurances with just one space.
                            let re = Regex::new(r"\s+").unwrap();
                            let elem = element.unwrap().text();
                            let result = re.replace_all(elem.as_str(), " ");

                            if Some(&result).is_none() || result.is_empty() {
                                continue
                            }
                            else {
                                if attr.contains("title") {
                                    rss_elemnts.push(RssElement {
                                        label: RssLabels::Title,
                                        name:  attr.to_string(),
                                        value: result.to_string()
                                    });
                                }
                                else if attr.contains("date") {
                                    rss_elemnts.push(RssElement {
                                        label: RssLabels::Date,
                                        name:  attr.to_string(),
                                        value: result.to_string()
                                    });
                                }
                                else if attr.contains("description") {
                                    rss_elemnts.push(RssElement {
                                        label: RssLabels::Description,
                                        name:  attr.to_string(),
                                        value: result.to_string()
                                    });
                                }
                                else if attr.contains("url") {
                                    rss_elemnts.push(RssElement {
                                        label: RssLabels::Url,
                                        name:  attr.to_string(),
                                        value: result.to_string()
                                    });
                                }
                                else {
                                    rss_elemnts.push(RssElement {
                                        label: RssLabels::Misc,
                                        name:  attr.to_string(),
                                        value: result.to_string()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    rss_elemnts
}

/// pub fn collector(reader_config: &RssConfig, max_page: u64, limit: bool) -> Result<<Vec<RssSection>>
/// Gets all the data from the URLs and parses the data to the Vec<RssSection>
pub fn collector(reader_config: &RssConfig,  
                 max_page: u64,
                 limit: bool) -> Result<Vec<RssSection>> {
    let local_max = match limit {
        true => {
            max_page
        },
        false => {
            std::u64::MAX - 1
        }
    };
    let mut reader_sections: Vec<RssSection> = Vec::new();
    for current_page in 0..local_max {
        let url = format!("{}?{}={}", &reader_config.uri.as_ref().unwrap(), reader_config.next.as_ref().unwrap(), current_page.to_string());
        // There's a issue with how TOKIO handles GET requests, if given a URL that doesn't return
        // a 200 OK status return code, the reqwest::blocking::get function will hange indefinitely
        let request = reqwest::blocking::get(&url).expect("WTF");
        match request.status() {
            // Continues on 200
            reqwest::StatusCode::OK => {
                let response_text = request.text();
                match response_text {
                    Ok(_) => {
                        let document = Document::from_read(response_text.unwrap().as_bytes());
                        if Some(&document).is_none() {
                            warn!("Url: {} does not exist", &url);
                            break;
                        }
                        else {
                            let messages = get_items(&document.unwrap(), 
                                            &reader_config.tags.as_ref().unwrap(), 
                                            &reader_config.sections.as_ref().unwrap(), 
                                            &reader_config.elements.as_ref().unwrap()
                                            );
                            if Some(&messages).is_none() {
                                continue;
                            }
                            reader_sections.push(RssSection {
                                url:      url,
                                page:     current_page,
                                section:  messages
                            });
                        }
                    },
                    Err(_) => {
                        warn!("No respose text");
                        continue;
                    }
                }
            }
            // Breaks on 301
            reqwest::StatusCode::MOVED_PERMANENTLY => {
                info!("Url: {} moved permanently -> {}", &url, request.headers().get("Location").unwrap().to_str().unwrap());
                break;
            }
            // Breaks on 401
            reqwest::StatusCode::UNAUTHORIZED => {
                warn!("Url: {} unauthorized", &url);
                break;
            }
            // Breaks on 404
            reqwest::StatusCode::NOT_FOUND => {
                warn!("Url: {} does not exist", &url);
                break;
            }
            // Breaks on any other result
            _ => {
                error!("Url: {} not supported http status code {}", &url, request.status().to_string());
                break;
            }
        }
    }
    info!("Done grabbing links");
    Ok(reader_sections)
}

/// pub fn get_first_entry(first_section: &RssSection) -> Option<String>
/// Gets the first entry in a RssSection
pub fn get_first_entry(first_section: &RssSection) -> Option<String> {
    let mut reader_first = String::from("");
    for element in &first_section.section {
        match element.name.as_str() {
            "title" => {
                reader_first = element.value.to_string();
                break;
            },
            _ => {
                continue;
            }
        }
    }
    Some(reader_first)
}

/// pub fn hasher<T>(data: T) -> u64
/// Hashes the struct in the generic typed field and returns a hash 
pub fn hasher<T>(data: T) -> u64 where T: Hash {
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}

/// pub fn rss_poll(rss_feed: &RssFeed, rss_opts: &RssOptions, rss_init: bool)
/// Polls the RssFeed with the RssOptions depending the on the rss_init variable
pub fn rss_poll(rss_feed: &RssFeed, rss_opts: &RssOptions, rss_init: bool) {
    if rss_init {
        info!("Writing RSS feed to file");
        match RssFeed::write_feed(&rss_opts.out, &rss_feed) {
            Ok(_) => {
            },
            Err(e) => {
                error!("{}", e);
            }
        }
        return
    }
    let new_entries = collector(&rss_feed.config, 1, rss_opts.limit);
    let new_first_entry = get_first_entry(new_entries.unwrap().first().unwrap());
    let new_hash = hasher(RssHash {
        title:     rss_feed.config.name.as_ref().unwrap().to_string(),
        desc:      rss_feed.config.description.as_ref().unwrap().to_string(),
        first:     new_first_entry.unwrap()
    });
    if &rss_feed.hash == &new_hash {
        info!("No updates for rss feed: {}", &rss_feed.config.name.as_ref().unwrap());
    }
    else {
        warn!("New hash: {}, old hash: {}", &new_hash.to_string(), &rss_feed.hash.to_string());
        info!("Writing RSS feed to file");
        match RssFeed::write_feed(&rss_opts.out, &rss_feed) {
            Ok(_) => {
            },
            Err(e) => {
                error!("{}", e);
            }
        }
    }
}

/// pub fn setup_config(app: &clap::ArgMatches, opts: &mut RssOptions) -> Option<RssConfig>
/// Sets up the RssConfig
pub fn setup_config(app: &clap::ArgMatches, opts: &mut RssOptions) -> Option<RssConfig> {
    if app.is_present("version") {
        info!("Version: {}", opts.version);
        std::process::exit(1);
    }

    if app.is_present("config") {
        opts.conf = match app.value_of("config") {
           Some(conf) => {
               conf.to_string()
           },
           _ => {
               error!("Config argument needs to be specified");
               std::process::exit(1);
           }
       };
    }
    else {
        warn!("Config not specified");
    }

    if app.is_present("read") {
        opts.init = false;
        opts.out = match app.value_of("read") {
            Some(out) => {
                info!("Using JSON database from command line");
                out.to_string()
            },
            _ => {
                error!("Read JSON database file not set");
                std::process::exit(1);
            }
        }

    }
    else {
        opts.init = true;
    }

    let reader_config: Option<RssConfig>;
    let rss_config: RssConfig;
    if opts.init {
        reader_config = match RssConfig::read_config(&opts.conf) {
            Ok(conf) => {
                Some(conf)
            },
            Err(_) => {
                None
            }
        };
    
        if reader_config.as_ref().is_none() {
            error!("Config is null");
        }
        else {
            info!("Config successfully read");
        }

        rss_config = reader_config.unwrap();
    }
    else {
        return None
    }

    if app.is_present("name") {
        opts.name = match app.value_of("name") {
            Some(name) => {
                info!("Using name on command line");
                name.to_string()
            },
            _ => {
                warn!("Name on command line invalid, using Untitled");
                "Untitled".to_string()
            }
        }
    }
    else {
        opts.name = match &rss_config.name {
            Some(name) => {
                info!("Using name from config");
                name.to_string()
            },
            _ => {
                warn!("Name not found, using Untitled");
                "Untitled".to_string()
            }
        }
    }

    if app.is_present("description") {
        opts.desc = match app.value_of("description") {
            Some(desc) => {
                info!("Using description on command line");
                desc.to_string()
            },
            _ => {
                warn!("Description on command line invalid, using Untitled");
                "Untitled".to_string()
            }
        }
    }
    else {
        opts.desc = match &rss_config.description {
            Some(desc) => {
                info!("Using description from config");
                desc.to_string()
            },
            _ => {
                warn!("Description not found, using Untitled");
                "Untitled".to_string()
            }
        }
    }

    if app.is_present("next") {
        opts.next = match app.value_of("next") {
            Some(next) => {
                info!("Using next on command line");
                next.to_string()
            },
            _ => {
                warn!("Next on command line invalid, only fetching the first page");
                "".to_string()
            }
        }
    }
    else {
        opts.next = match &rss_config.next {
            Some(next) => {
                info!("Using next from config");
                next.to_string()
            },
            _ => {
                warn!("Next not found, only fetching the first page");
                "".to_string()
            }
        }
    }

    if app.is_present("output") {
        opts.out = match app.value_of("output") {
            Some(out) => {
                out.to_string()
           },
           _ => {
               error!("Output argument needs to be specified");
               std::process::exit(1);
           }
        };
    }
    else {
        error!("Out argument needs to be specified");
        std::process::exit(1);
    }

    if app.is_present("max") {
        opts.max = match app.value_of("max") {
            Some(max) => {
                opts.limit = true;
                max.parse::<u64>().unwrap()
            },
            _ => {
                warn!("Max page value not specified, using unlimited");
                opts.limit = false;
                0
            }
        };
    }
    else {
        opts.max = match &rss_config.max {
            Some(max) => {
                info!("Using max from config");
                opts.limit = true;
                *max
            },
            _ => {
                warn!("Max not found, going unlimited");
                opts.limit = false;
                0
            }
        }
    }

    if app.is_present("timeout") {
        opts.timeout = match app.value_of("timeout") {
            Some(timeout) => {
                timeout.parse::<u64>().unwrap()
            },
            _ => {
                warn!("Timeout not set, using default");
                0
            }
        }
    }
    else {
        opts.timeout = match &rss_config.timeout {
            Some(timeout) => {
                info!("Using timeout from config");
                *timeout
            },
            _ => {
                warn!("Timeout not found, using default: 0");
                0
            }
        }
    }

    if app.is_present("url") {
        opts.url = match app.value_of("url") {
            Some(url) => {
                info!("Using URI from command line");
                url.to_string()
            },
            _ => {
                warn!("URI not set, trying config");
                "".to_string()
            }
        }
    }
    else {
        opts.url = match &rss_config.uri {
            Some(uri) => {
                info!("Using URI from config");
                uri.to_string()
            },
            _ => {
                error!("URI not found");
                std::process::exit(1);
            }
        }
    }

    Some(rss_config)
}

/// pub fn setup_logging()
/// Sets up the default logging level for the application using tracing
pub fn setup_logging() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }

    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
}

/// pub fn setup_arguments()
/// Sets up the arguments of the program and returns a clap::ArgMatches
pub fn setup_arguments() -> clap::ArgMatches<'static> {  
    App::new("rss-parser")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("0.1")
        .author("c0z <c0z@c0z.red>")
        .about("A rss-parser for websites without a rss feed")
        .arg(Arg::with_name("timeout")
             .short("t")
             .long("timeout")
             .value_name("u64")
             .help("Sets the timeout of the parsing engine before moving on")
             .takes_value(true))
        .arg(Arg::with_name("version")
             .short("v")
             .long("version")
             .help("version of the program")
             .takes_value(false))
        .arg(Arg::with_name("output")
             .short("o")
             .long("output")
             .help("The output file the results will be saved in")
             .takes_value(true))
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .help("Config to parse webpage")
             .group("file")
             .takes_value(true))
        .arg(Arg::with_name("read")
             .short("r")
             .long("read")
             .help("JSON file with parsed data to be read")
             .group("file")
             .takes_value(true))
        .arg(Arg::with_name("url")
             .short("u")
             .long("url")
             .help("The url argument is the URI of the RSS website")
             .takes_value(true))
        .arg(Arg::with_name("max")
             .short("m")
             .long("max")
             .help("Set the max page (u64) the site goes up to")
             .takes_value(true))
        .arg(Arg::with_name("next")
             .short("x")
             .long("next")
             .help("Set the URL parameter that will be used to change pages")
             .takes_value(true))
        .arg(Arg::with_name("name")
             .short("n")
             .long("name")
             .help("Name the RSS feed")
             .takes_value(true))
        .arg(Arg::with_name("description")
             .short("d")
             .long("description")
             .help("Set the RSS feed description")
             .takes_value(true))
        .get_matches()
}

/// The tokio::main function that is based on async Result<_, _> and function calling
#[tokio::main]
pub async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    setup_logging();

    let rss_opts = &mut RssOptions { 
        version: "0.1".to_string(), 
        timeout: 0,
        ..Default::default()
    };

    let rss_app = setup_arguments();
    let rss_config = setup_config(&rss_app, rss_opts);
    let rss_date = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    
    if rss_opts.init {
        if rss_config.is_some() {
            let rss_conf = rss_config.unwrap();
            let rss_sections = collector(&rss_conf, rss_opts.max, rss_opts.limit)?;
            let rss_first = get_first_entry(&rss_sections.first().unwrap());
            let rss_hash = hasher(RssHash {
                    title: rss_conf.name.as_ref().unwrap().to_string(),
                    desc:  rss_conf.description.as_ref().unwrap().to_string(),
                    first: rss_first.unwrap()
            });
            info!("Before clone");
            let rss_feed = RssFeed {
                    date:     rss_date.unwrap().as_secs(),
                    hash:     rss_hash,
                    config:   rss_conf,
                    sections: rss_sections
            };
            // Polling
            info!("Creating initialization JSON db: {}", &rss_feed.config.name.as_ref().unwrap());
            rss_poll(&rss_feed, &rss_opts, rss_opts.init);
        }
        else {
            error!("Failed to load JSON Config")
        }
    }
    else {
        let rss_feed: RssFeed = match RssFeed::read_feed(&rss_opts.out) {
            Ok(feed) => {
                feed
            },
            Err(_) => {
                error!("JSON database failed JSON read_feed");
                std::process::exit(1);
            }
        };
        info!("Polling: {}", &rss_feed.config.name.as_ref().unwrap());
        rss_poll(&rss_feed, &rss_opts, rss_opts.init);
    }
    Ok(())
}
