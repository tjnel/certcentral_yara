import "pe"

rule MAL_Compromised_Cert_MeshAgent_Certum_546256D12BE056C7089A2BA1908762E1 {
   meta:
      description         = "Detects MeshAgent with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-16"
      version             = "1.0"

      hash                = "6f9339f47bc3d9566a5a3b0e1ea79b4e0666b0c8dc638486a3f648c501f0b672"
      malware             = "MeshAgent"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jasmine Shania Harris"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "54:62:56:d1:2b:e0:56:c7:08:9a:2b:a1:90:87:62:e1"
      cert_thumbprint     = "54F4165933A1158585A2535D3ADCB4407B4A0148"
      cert_valid_from     = "2025-10-16"
      cert_valid_to       = "2026-10-16"

      country             = "US"
      state               = "Florida"
      locality            = "Miramar"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "54:62:56:d1:2b:e0:56:c7:08:9a:2b:a1:90:87:62:e1"
      )
}
