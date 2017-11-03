FILENAME=isamon
OUTPUT_PDF=manual
login=xhanze10

all: pdf

$(OUTPUT_PDF).pdf: pdf

pdf: ps
	ps2pdf -sPAPERSIZE=a4 $(FILENAME).ps $(OUTPUT_PDF).pdf

pdf-print: ps
	ps2pdf -dColorConversionStrategy=/LeaveColorUnchanged -dPDFSETTINGS=/printer $(FILENAME).ps

text: html
	html2text -width 100 -style pretty $(FILENAME)/$(FILENAME).html | sed -n '/./,$$p' | head -n-2 >$(FILENAME).txt

html:
	@#latex2html -split +0 -info "" -no_navigation $(FILENAME)
	htlatex $(FILENAME)

ps:	dvi
	dvips -t letter $(FILENAME).dvi

dvi:
	latex $(FILENAME)
	bibtex $(FILENAME)||true
	latex $(FILENAME)
	latex $(FILENAME)

read:
	evince $(FILENAME).pdf &

aread:
	acroread $(FILENAME).pdf

clean:
	rm -f $(FILENAME).{ps,pdf,log,aux,out,dvi,bbl,blg,toc} $(OUTPUT_PDF).pdf

pack:
	tar czf $(login)-fit.tar.gz "$(FILENAME).tex" czechiso.bst references.bib Makefile
