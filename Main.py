import Smali.Dex as Dex
import Smali.Encoders as Encoder

dex = Dex.Dex("classes.dex")
print(dex.getClass(2336))
