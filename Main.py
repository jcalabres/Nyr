from Smali.Dex import *
from Smali.Analyzer import *

dex = Dex("classes.dex")
#print(dex.getClass(791))
#print(Analyzer.overview(dex))
print(dex.findClass("SplashActivity")[0])
