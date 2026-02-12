import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_2423453A99B347263BBBA607F4F55FAB {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-11"
      version             = "1.0"

      hash                = "bcd7a7a77859184ce14ce7e9e7649b4e37a37129528c867fcf5b1a9726916f84"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "The malware was distributed disguised as a invoice document, connects to the domain ssagntroplexa[.]com"

      signer              = "CORE OPERATING SYSTEM LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "24:23:45:3a:99:b3:47:26:3b:bb:a6:07:f4:f5:5f:ab"
      cert_thumbprint     = "52DDE3E85F79594473B2AE3239AD4369D1360E1F"
      cert_valid_from     = "2025-11-11"
      cert_valid_to       = "2028-11-10"

      country             = "US"
      state               = "Florida"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "L25000493456"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "24:23:45:3a:99:b3:47:26:3b:bb:a6:07:f4:f5:5f:ab"
      )
}
