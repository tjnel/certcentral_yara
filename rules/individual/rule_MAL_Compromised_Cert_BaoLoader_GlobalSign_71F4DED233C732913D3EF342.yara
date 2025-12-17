import "pe"

rule MAL_Compromised_Cert_BaoLoader_GlobalSign_71F4DED233C732913D3EF342 {
   meta:
      description         = "Detects BaoLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-29"
      version             = "1.0"

      hash                = "bd48834ed8fd535fce2749bf63133fa4ddbd43cf582fb9651568adead625f61a"
      malware             = "BaoLoader"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was originally used for adfraud but is a risk due to an arbitrary backdoor. For more information see https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/ and https://www.gdatasoftware.com/blog/2025/08/38257-appsuite-pdf-editor-backdoor-analysis"

      signer              = "Byte Media Sdn. Bhd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "71:f4:de:d2:33:c7:32:91:3d:3e:f3:42"
      cert_thumbprint     = "17F77710C888E30917F71F7909086BCC2D131F61"
      cert_valid_from     = "2024-08-29"
      cert_valid_to       = "2027-08-30"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "info@byte-media.net"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "71:f4:de:d2:33:c7:32:91:3d:3e:f3:42"
      )
}
