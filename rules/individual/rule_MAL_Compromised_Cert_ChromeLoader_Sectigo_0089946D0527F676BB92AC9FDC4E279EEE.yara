import "pe"

rule MAL_Compromised_Cert_ChromeLoader_Sectigo_0089946D0527F676BB92AC9FDC4E279EEE {
   meta:
      description         = "Detects ChromeLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-11"
      version             = "1.0"

      hash                = "212eb5b7ac669a74dfd1a6e5fbd4f4e187453f43aa0a57b9aaeeef747e9cc10a"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Innova Media d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:89:94:6d:05:27:f6:76:bb:92:ac:9f:dc:4e:27:9e:ee"
      cert_thumbprint     = "6D8E976DD2C394244CC72BCCCD6379EBAB7A06EE"
      cert_valid_from     = "2024-12-11"
      cert_valid_to       = "2025-12-11"

      country             = "SI"
      state               = "Šempeter-Vrtojba"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:89:94:6d:05:27:f6:76:bb:92:ac:9f:dc:4e:27:9e:ee"
      )
}
