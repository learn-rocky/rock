VERSION		= 1.0
RELEASE		= 2
DATE		= $(shell date)
NEWRELEASE	= $(shell echo $$(($(RELEASE) + 1)))
PROJECT_NAME    = rock
TOPDIR = $(shell pwd)
MANPAGES = 
A2PS2S1C  = /bin/a2ps --sides=2 --medium=Letter --columns=1 --portrait --line-numbers=1 --font-size=8
A2PSTMP   = ./tmp
DOCS      = ./docs

SHELL := /bin/bash

.PHONY: all

all: help
#https://stackoverflow.com/questions/6273608/how-to-pass-argument-to-makefile-from-command-line
args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`
%:
	@:

versionfile:
	echo "version:" $(VERSION) > etc/version
	echo "release:" $(RELEASE) >> etc/version
	echo "source build date:" $(DATE) >> etc/version

manpage:
	for manpage in $(MANPAGES); do (pod2man --center=$$manpage --release="" ./docs/$$manpage.pod > ./docs/$$manpage.1); done

build: clean 
	$(PYTHON) setup.py build -f

clean: cleantmp
	-rm -rf *~ rock/target
	-rm -rf rpm-build/
	-rm -rf docs/*.1
	-find . -type f -name *.pyc -exec rm -f {} \;
	-find . -type f -name *~  -exec rm -f {} \;

clean_hard:
	-rm -rf $(shell $(PYTHON) -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")/adagios 

#Ref: https://stackoverflow.com/questions/1490949/how-to-write-loop-in-a-makefile
# MANIFEST  
SRC1= Makefile 
SRC2= 
#SRC2= manage.py profiles_projects-dir-layout.txt

cleantmp:
	rm -f ${A2PSTMP}/*.ps ${A2PSTMP}/*.pdf	

.ps: cleantmp
	$(foreach var, $(SRC1), ${A2PS2S1C} $(var) --output=${A2PSTMP}/$(var).ps ;)
	$(foreach var, $(SRC2), ${A2PS2S1C} $(var) --output=${A2PSTMP}/$(var).ps ;)
	touch .ps

allpdf: .pdf
	make -C profiles_api pdf
	make -C profiles_project pdf
	touch .pdf

.pdf: .ps
	$(foreach var, $(SRC1), (cd ${A2PSTMP};ps2pdf $(var).ps $(var).pdf);)
	$(foreach var, $(SRC2), (cd ${A2PSTMP};ps2pdf $(var).ps $(var).pdf);)
	rm -f ${A2PSTMP}/*.ps
	cp ${A2PSTMP}/*.pdf  ${DOCS}/
	touch .pdf
tree: clean
	tree -L 4 > ${PROJECT_NAME}-dir-layout.txt

test:
	(cd rock && cargo build && sudo target/debug/rock -h)

.go-setup:
	go get gopkg.in/yaml.v2
	touch .go-setup

srpmproc:
	git clone https://git.rockylinux.org/release-engineering/public/srpmproc.git

srpmproc/srpmproc: srpmproc
	cd srpmproc; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/srpmproc

install_srpmproc: srpmproc/srpmproc .dnf .system
	sudo cp -r etc_mock/rocky* /etc/mock/
	sudo cp -r etc_mock/templates/* /etc/mock/templates/
	sudo install -m 755 srpmproc/srpmproc /usr/local/bin/
	sudo install -m 755 bin/* /usr/local/bin/
	test -d /usr/share/nginx/html/repo || mkdir /usr/share/nginx/html/repo
	sudo chmod 777 /usr/share/nginx/html/repo


# enable makefile to accept argument after command
#https://stackoverflow.com/questions/6273608/how-to-pass-argument-to-makefile-from-command-line

args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`
%:
	@:
status:
	git status
commit:
	git commit -am "$(call args, Automated commit message without details, Please read the git diff)"  && git push
pull:
	git pull
help:
	@echo "Usage: make <target> <argument>"
	@echo
	@echo "Available targets are:"
	@echo "  all                    Default to help"
	@echo "  test                   rock test run by cargo"
	@echo "  help                   Showing this help "
	@echo "  install                Install rock binary locally"
	@echo "  install_srpmproc       Install srpmproc Go binary locally"
	@echo "  get rpm1               rock get rpm1"
	@echo "  build rpm1             rock build rpm1"
	@echo "  mkcfg rpm1             rock mkcfg rpm1"
	@echo "  prep rpm1              rock prep  rpm1"
	@echo "  patch rpm1             rock patch rpm1"
	@echo "  clean                  clean myrocky and srpmproc "
	@echo "  commit {"my message"}  git commit, without or with real commit message"
	@echo "  status                 git status"
	@echo "  pull                   git pull"
	@echo ""


