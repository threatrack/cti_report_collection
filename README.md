**This is a preliminar work in progress. The IOCs in `url`, `hostname`, `ipv4`, etc. folders are full of false positives! DO NOT USE!**

# Threat Intelligence Report Repository

Repository collecting and automagically processing public threat intelligence reports.

## Dependencies

On CentOS 7 install dependencies via:

```
yum install yara poppler-utils ghostscript python3 python3-pip curl pandoc wkhtmltopdf
pip3.6 install -U threatrack_iocextract
```

**Only tested with CentOS 7.**

## Usage

Add reports to `reports.csv` one per line, formated as:

```
"date","source","name","filetype","url"
```

Reports and IOC files will be named `{text,html,pdf,yara,...}/$date-$source-$name.{txt,html,pdf,yar,...}`

Then run **`./process.sh`** to automagically:

1. download the reports to `html/` or `pdf/` depending on `filetype` in `reports.csv`
2. convert `html/` reports to `pdf/`
3. convert the reports to plaintext into `text/`
4. extract various IOCs and rules into `yara/`, `snort/`, `ipv4/`, `url/`, `hostname/`, etc.

Optionally, you can run **./webarchive.sh** to safe the URLs via <http://sweb.archive.org/safe/>.

## Issues

- Because all processing is automatic, **there are many false positives**.
- Extracted Snort rules are currently not checked, so may not work.
- Some sources protect against scraping of their reports. These are still scrapped but the extracted data maybe incomplete. These include:
	- IBM IRIS: Requires "Continue reading" Javascript button to be pressed
	- Cylance: Requires email and company name
	- Fireeye: Uses Incapsula

## TODO

- Automagically download samples to `samples/$date-$source-$name/*`
- Fix sources that protect against scraping.
- `process.sh`: Handle `txt` and `yara` `filetype`s in `reports.csv`.
- Add 2018, 2017, 2016, ...
- Add victimology
- Make `webarchive.sh` only safe URLs to <http://sweb.archive.org/safe/> if not already safed.

