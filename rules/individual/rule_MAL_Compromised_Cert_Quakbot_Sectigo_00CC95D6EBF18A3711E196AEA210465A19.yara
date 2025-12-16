import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00CC95D6EBF18A3711E196AEA210465A19 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-26"
      version             = "1.0"

      hash                = "f86eb10a728b912bfb98529ccc0e2dfedfe1bda9b12b8556dba19f810720a567"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "GEN Sistemi, d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:cc:95:d6:eb:f1:8a:37:11:e1:96:ae:a2:10:46:5a:19"
      cert_thumbprint     = "319F0E03F0F230629258C7EA05E7D56EAD830CE9"
      cert_valid_from     = "2021-02-26"
      cert_valid_to       = "2022-02-26"

      country             = "SI"
      state               = "???"
      locality            = "Hajdina"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:cc:95:d6:eb:f1:8a:37:11:e1:96:ae:a2:10:46:5a:19"
      )
}
