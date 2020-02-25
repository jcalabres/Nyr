import Smali.Dex as Dex
import Smali.Encoders as Encoder

dex = Dex.Dex("orchid.classes.dex")
print(dex.getClass(757))
print(dex.overview())
#dex = Dex.Dex("orchid.classes2.dex")
#print(dex.getClass(757))