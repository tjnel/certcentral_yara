import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_5886E0F4BAA836E9231BA6F8F965E51D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "ddfd45fd76607ba94debe6255019c8ceaaa1417ff3af3ca15cec029cc065750b"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware executes powershell to send information about the infection to Telegram and then drops and executes an installer for ScreenConnect https://tria.ge/251217-nz5dlswqhr/behavioral1"

      signer              = "Taiyuan Tataomi Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "58:86:e0:f4:ba:a8:36:e9:23:1b:a6:f8:f9:65:e5:1d"
      cert_thumbprint     = "A4BD88661CF293FBC29B6648C0EC1AC5FC32DB37"
      cert_valid_from     = "2025-08-22"
      cert_valid_to       = "2026-08-22"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91140105MADC8HF4XN"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "58:86:e0:f4:ba:a8:36:e9:23:1b:a6:f8:f9:65:e5:1d"
      )
}
