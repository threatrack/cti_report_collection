#!/bin/bash

curlcmd="curl --user-agent \"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:40.0) Gecko/20100101 Firefox/40.0\" --compressed"

mkdir -p html
mkdir -p text
#mkdir -p markdown
mkdir -p pdf
mkdir -p yara
mkdir -p broken-yara
mkdir -p snort
mkdir -p hash
mkdir -p hostname
mkdir -p url
mkdir -p ipv4

tmp="$(mktemp)"

cat reports.csv | while read line; do
	date="$(echo "${line}" | sed 's/^"//g;s/"$//g' |  awk -F'","' '{print $1}')"
	author="$(echo "${line}" | sed 's/^"//g;s/"$//g' |  awk -F'","' '{print $2}')"
	name="$(echo "${line}" | sed 's/^"//g;s/"$//g' |  awk -F'","' '{print $3}')"
	filetype="$(echo "${line}" | sed 's/^"//g;s/"$//g' |  awk -F'","' '{print $4}')"
	url="$(echo "${line}" | sed 's/^"//g;s/"$//g' |  awk -F'","' '{print $5}')"
	filename="${date}-${author}-${name}"

	html="html/${filename}.html"
	text="text/${filename}.txt"
	markdown="markdown/${filename}.md"
	pdf="pdf/${filename}.pdf"
	yara="yara/${filename}.yar"
	brokenyara="broken-yara/${filename}.yar"
	snort="snort/${filename}.rules"
	hashes="hash/${filename}.txt"
	hostname="hostname/${filename}.txt"
	urls="url/${filename}.txt"
	ipv4="ipv4/${filename}.txt"

	echo "[$] Processing ${filename} ------------------"

	# TODO: gets rate limited :(
	#echo "	[+] Archiving via web.archive.org/save/"
	#curl "https://web.archive.org/save/${url}" > /dev/null

case "${filetype}" in
	"html")
		if [ ! -f "${html}" ]; then
			echo "	[+] Downloading: ${html}"
			eval "${curlcmd} \"${url}\" -o \"${html}\""
		else
			echo "	[.] We already have: ${html}"	
		fi
	
		if [ ! -f "${text}" ]; then
			echo "	[+] Converting to: ${text}"
			#cat "${html}" | html2text > "${text}"
			pandoc -f html "${html}" -t plain > "${text}"
		else
			echo "	[.] Already converted to: ${text}"
		fi
	
#		if [ ! -f "${markdown}" ]; then
#			echo "	[+] Converting to: ${markdown}"
#			pandoc -f html ${html} -t markdown -o "${markdown}"
#		else
#			echo "	[.] Already converted to: ${markdown}"
#		fi
	
		if [ ! -f "${pdf}" ]; then
			echo "	[+] wkthmltopdf to: ${tmp}"
			wkhtmltopdf -gl -s A4 -T 2 -B 2 -n "${url}" "${tmp}"
			echo "	[+] Shrinking PDF to: ${pdf}"
			ps2pdf -dPDFSETTINGS=/ebook -dGrayImageResolution=150 "${tmp}" "${pdf}"
		else
			echo "	[.] PDF already exists: ${pdf}"
		fi

		;;

	"pdf")
		if [ ! -f "${pdf}" ]; then
			echo "	[+] Downloading: ${tmp}"
			eval "${curlcmd} \"${url}\" -o \"${tmp}\""
			echo "	[+] Shrinking PDF to: ${pdf}"
			ps2pdf -dPDFSETTINGS=/ebook -dGrayImageResolution=150 "${tmp}" "${pdf}"
		else
			echo "	[.] PDF already exists: ${pdf}"
		fi

		if [ ! -f "${text}" ]; then
			echo "	[+] Converting to: ${text}"
			pdftotext "${pdf}" "${text}"
		else
			echo "	[.] Already converted to: ${text}"
		fi

		;;

	*)
		echo "	[-] ERROR: Can't process filetype ${filetype}"

esac

	if [ -f "${text}" ]; then
		if [ ! -f "${yara}" ] && [ ! -f "${brokenyara}" ]; then
			echo "	[+] Extracting YARA rules: ${yara}"
			python3.6 ruleextract.py "${text}" yara > "${yara}"
			if ! yara "${yara}" /dev/null || [ $(wc -c < ${yara}) -lt 3 ]; then
				mv "${yara}" "${brokenyara}"
			fi
		else
			echo "	[.] YARA rules already extracted to: ${yara}"
		fi

		if [ ! -f "${snort}" ]; then
			echo "	[+] Extracting Snort rules: ${snort}"
			python3.6 ruleextract.py "${text}" snort > "${snort}"
		else
			echo "	[.] Snort rules already extracted to: ${snort}"
		fi

		if [ ! -f "${hashes}" ]; then
			echo "	[+] Extracting hashes to: ${hashes}"
			python3.6 ruleextract.py "${text}" hash > "${hashes}"
		else
			echo "	[.] Hashes already extracted to: ${hashes}"
		fi

		if [ ! -f "${hostname}" ]; then
			echo "	[+] Extracting domain IOCs to: ${hostname}"
			python3.6 ruleextract.py "${text}" hostname > "${hostname}"
		else
			echo "	[.] Domain IOCs already extracted to: ${hostname}"
		fi

		if [ ! -f "${urls}" ]; then
			echo "	[+] Extracting URLs to: ${urls}"
			python3.6 ruleextract.py "${text}" url > "${urls}"
		else
			echo "	[.] URLs already extracted to: ${urls}"
		fi

	else
		echo "	[-] ERROR: ${text} does not exist"
	fi
	

done

rm "${tmp}"


