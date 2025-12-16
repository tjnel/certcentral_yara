import "pe"

rule MAL_Compromised_Cert_FakeDocument_Sectigo_75F97FA8095F9167F552859E01DBFF77 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-16"
      version             = "1.0"

      hash                = "1d37ba51451af1501ad98ec080bcdd3bcd7ccacb62c73bfea5a2521422a10702"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "This malicious build is involved in a malware campaign, disguised as a PDF document under a fake Candidate Assignment package - ea2c061b2f5710ed43c303269a56de67820509f3b3c58972ae59daf576a30c8a"

      signer              = "BonJoe Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "75:f9:7f:a8:09:5f:91:67:f5:52:85:9e:01:db:ff:77"
      cert_thumbprint     = "0C36AFC555CEF188364A54091DC9B70E124495C3"
      cert_valid_from     = "2025-10-16"
      cert_valid_to       = "2026-10-16"

      country             = "CN"
      state               = "Jiangsu Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91320115MA1WKJMU43"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "75:f9:7f:a8:09:5f:91:67:f5:52:85:9e:01:db:ff:77"
      )
}
