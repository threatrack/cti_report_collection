**This is a preliminar work in progress. The IOCs in `url`, `hostname`, `ipv4`, etc. folders are full of false positives! DO NOT USE!**
**Snort rules are extracted but untested. Mostly won't work due to linebreaks. Adjust manually.**

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

Optionally, you can run **./webarchive.sh** to safe the URLs via <https://web.archive.org/save/>.

## Issues

- Because all processing is automatic, **there are many false positives**.
- Extracted Snort rules are currently not checked, so may not work.
- Some sources protect against scraping of their reports. These are still scrapped but the extracted data maybe incomplete. These include:
	- IBM IRIS: Requires "Continue reading" Javascript button to be pressed
	- Cylance: Requires email and company name
	- Fireeye: Uses Incapsula

## TODO

- Make `webarchive.sh` only safe URLs to <https://web.archive.org/save/> if not already saved. Workaround: Just Ctrl+C after the entries are saved.
- Automagically download samples to `samples/$date-$source-$name/*`
- Fix sources that protect against scraping.
- `process.sh`: Handle `txt` and `yara` `filetype`s in `reports.csv`.
- `process.sh`: Handle `github` IOC repositories (see "20191017","eset","apt29","github","https://github.com/eset/malware-ioc/tree/master/dukes")
- Fallback to web.archive.org links in case original source URL is down.
- Add 2018, 2017, 2016, ...
- Eventually regenerate all IOCs with processing bugs fixed
- Add victimology
- Find method to compress vendor supplied PDFs better.
- Test and fix extracted snort rules
- Partially addressed (needs check if fully fixed): IOCs in tables with linebreaks are not parsed correctly (see 20191010-amnesty-morocco_nso for problem)
- Extract `-----BEGIN PUBLIC KEY-----`; needs implementation in threatrack_iocextract
- CIDRs are detected as IPs; needs fix in threatrack_iocextract
- Maybe remove Twitter, Pastebin and Github domains from whitelist to extract as IOCs in case malware uses them as C&C (see 20191017-eset-apt29, 20191024-checkpoint-rig_ek)
- Extract user-agent strings (see text/20190809-chronicle-gossipgirl_duqu15.txt); needs support in threatrack_iocextract
- Fix misc yara extraction error (see yara/20190809-chronicle-gossipgirl_stuxshop.yar(7): error: unterminated string), needs fix in threatrack_iocextract
- Fix yara not detecting imports (see yara/20191010-fireeye-mahalo_fin7.yar(8): error: undefined identifier "pe"), needs fix in threatrack_iocextract
- **Extract URLs without scheme; needs fix in threatrack_iocextract**
- **Add extraction for IOCs in Github** (see <https://github.com/eset/malware-ioc/tree/master/winnti_group>)

