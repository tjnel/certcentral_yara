import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_6A241FFE96A6349DF608D22C02942268 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-11"
      version             = "1.0"

      hash                = "f01877dc957f31702ff592478646c66b44abb7c02d40f20031de3a7b98b28e2b"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "HELP, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68"
      cert_thumbprint     = "ADE0A549A3BB9D11F588E5DF22DD921315B96813"
      cert_valid_from     = "2020-11-11"
      cert_valid_to       = "2021-11-11"

      country             = "SI"
      state               = "???"
      locality            = "Škofja Loka"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68"
      )
}
