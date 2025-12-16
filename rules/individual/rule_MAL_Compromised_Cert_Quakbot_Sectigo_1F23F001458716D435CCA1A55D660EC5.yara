import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_1F23F001458716D435CCA1A55D660EC5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-09"
      version             = "1.0"

      hash                = "e187fbf6543d1993f0945c04ee520600b6493236bae169a020f9a10c547e249d"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "OOO Ringen"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5"
      cert_thumbprint     = "B35AFD1621F148C65259EA13014DD745383E6483"
      cert_valid_from     = "2020-10-09"
      cert_valid_to       = "2021-10-09"

      country             = "RU"
      state               = "???"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5"
      )
}
