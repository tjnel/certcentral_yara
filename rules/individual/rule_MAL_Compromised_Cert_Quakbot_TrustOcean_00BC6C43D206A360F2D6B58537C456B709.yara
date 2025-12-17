import "pe"

rule MAL_Compromised_Cert_Quakbot_TrustOcean_00BC6C43D206A360F2D6B58537C456B709 {
   meta:
      description         = "Detects Quakbot with compromised cert (TrustOcean)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-25"
      version             = "1.0"

      hash                = "77abaa92184007a6176bf62098a90cf705254fae15ba25bcf2cd4359ca708428"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "ANKADA GROUP, d.o.o."
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "00:bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09"
      cert_thumbprint     = "E30264DC33571BB02647190AC8191B8439631380"
      cert_valid_from     = "2021-03-25"
      cert_valid_to       = "2022-03-25"

      country             = "SI"
      state               = "???"
      locality            = "Prosenjakovci - Pártosfalva"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "00:bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09"
      )
}
