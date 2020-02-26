from Smali.Dex import *
from Smali.Analyzer import *

dex = Dex("classes.dex")
#print(dex.getClassByName("Ls/h/e/l/l/S;"))
print(dex.getClass(791))
print(Analyzer.overview(dex))
