from Smali.Dex import *
from Smali.Analyzer import *

dex = Dex("classes.dex")
print(dex.getClass(791))