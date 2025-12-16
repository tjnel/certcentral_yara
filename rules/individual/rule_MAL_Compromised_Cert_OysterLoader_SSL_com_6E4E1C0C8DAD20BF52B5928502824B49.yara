import "pe"

rule MAL_Compromised_Cert_OysterLoader_SSL_com_6E4E1C0C8DAD20BF52B5928502824B49 {
   meta:
      description         = "Detects OysterLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-19"
      version             = "1.0"

      hash                = "1c9dfbc336b6b7a4ce7c101d51edd3f0a3fee7ed9fe79d634268486078c446d7"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "SMI Consulting GmbH"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "6e:4e:1c:0c:8d:ad:20:bf:52:b5:92:85:02:82:4b:49"
      cert_thumbprint     = "1360EB62C6FA8E75299C2C8810CFA68E57F197E5"
      cert_valid_from     = "2025-08-19"
      cert_valid_to       = "2026-08-19"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "6e:4e:1c:0c:8d:ad:20:bf:52:b5:92:85:02:82:4b:49"
      )
}
