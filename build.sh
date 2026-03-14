#!/bin/bash

DEST_DIR=${HOME}/.local/bin/oscmix

make clean
make all
make tools/regtool
make web

echo $PWD
cp alsarawio $DEST_DIR
cp alsaseqio $DEST_DIR
cp oscmix $DEST_DIR

cp ./tools/regtool ${DEST_DIR}/tools
cp ./gtk/oscmix-gtk ${DEST_DIR}/gtk
sudo cp -R ./web/pub/* /var/www/html/oscmix/
