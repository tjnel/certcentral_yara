import "pe"

rule MAL_Compromised_Cert_Grandoreiro_GlobalSign_498987CF459C6B2ACC0A647E {
   meta:
      description         = "Detects Grandoreiro with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-24"
      version             = "1.0"

      hash                = "1464ab9f175dd1a88139a9fe2fcd596e580fad5764ecc75251ca4cd7e3b6ec30"
      malware             = "Grandoreiro"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ROASTED BEANS PTY LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:89:87:cf:45:9c:6b:2a:cc:0a:64:7e"
      cert_thumbprint     = "85af78df310a96c1822cea98688ae07b459c3ec830e4aaf3df34540655fd83e3"
      cert_valid_from     = "2024-06-24"
      cert_valid_to       = "2025-06-01"

      country             = "AU"
      state               = "QUEENSLAND"
      locality            = "ROBINA"
      email               = "admin@roasted-beans.co"
      rdn_serial_number   = "087 245 243"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:89:87:cf:45:9c:6b:2a:cc:0a:64:7e"
      )
}
