import "pe"

rule MAL_Compromised_Cert_IcedID_SSL_com_40E27B7404AA9B485F8A2FC0C8E53AF3 {
   meta:
      description         = "Detects IcedID with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-27"
      version             = "1.0"

      hash                = "d033105288280266f0336365245e18984c5fc684577beed5ad7430775ecd7c02"
      malware             = "IcedID"
      malware_type        = "Initial access tool"
      malware_notes       = "A malware initially created as a banking trojan but then transitioned to initial access tool used by ransomware gangs: https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid and https://www.proofpoint.com/us/blog/threat-insight/first-step-initial-access-leads-ransomware"

      signer              = "Southern Wall Systems, LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "40:e2:7b:74:04:aa:9b:48:5f:8a:2f:c0:c8:e5:3a:f3"
      cert_thumbprint     = "CA468FF8403A8416042705E79DBC499A5EA9BE85"
      cert_valid_from     = "2023-03-27"
      cert_valid_to       = "2024-03-26"

      country             = "US"
      state               = "Alabama"
      locality            = "Dothan"
      email               = "???"
      rdn_serial_number   = "000 - 426 - 269"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "40:e2:7b:74:04:aa:9b:48:5f:8a:2f:c0:c8:e5:3a:f3"
      )
}
