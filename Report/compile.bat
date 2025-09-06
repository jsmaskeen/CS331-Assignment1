
set MAIN=report

REM First LaTeX pass
pdflatex -interaction=nonstopmode %MAIN%.tex

bibtex %MAIN%

REM Two more LaTeX passes
pdflatex -interaction=nonstopmode %MAIN%.tex
pdflatex -interaction=nonstopmode %MAIN%.tex

echo :3 Compilation finished. Output: %MAIN%.pdf

