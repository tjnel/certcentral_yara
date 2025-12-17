import "pe"

rule MAL_Compromised_Cert_ServHelper_Sectigo_44FE73F320AA8B7B4F5CA910AA22333A {
   meta:
      description         = "Detects ServHelper with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-04"
      version             = "1.0"

      hash                = "b436fbb05650df4facc948f49ee619c4825e747c373f2d461d5a1c26b0c7aa15"
      malware             = "ServHelper"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alpeks LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "44:fe:73:f3:20:aa:8b:7b:4f:5c:a9:10:aa:22:33:3a"
      cert_thumbprint     = "E952EB51416AB15C0A38B64A32348ED40B675043"
      cert_valid_from     = "2021-05-04"
      cert_valid_to       = "2022-05-04"

      country             = "RU"
      state               = "???"
      locality            = "Sankt-Peterburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "44:fe:73:f3:20:aa:8b:7b:4f:5c:a9:10:aa:22:33:3a"
      )
}
