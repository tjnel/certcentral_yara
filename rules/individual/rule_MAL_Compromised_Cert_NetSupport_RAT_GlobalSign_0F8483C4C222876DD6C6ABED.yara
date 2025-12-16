import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_GlobalSign_0F8483C4C222876DD6C6ABED {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-24"
      version             = "1.0"

      hash                = "06dec1d05b77f765b9d12c223d4b7887dc0a526e8d8a790bd2b99346619dc837"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Shanghai Lijin Chemical Technology Development Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0f:84:83:c4:c2:22:87:6d:d6:c6:ab:ed"
      cert_thumbprint     = "BA413448EFA6BAEC05C37262FDFC5CCAE0639A93"
      cert_valid_from     = "2024-05-24"
      cert_valid_to       = "2025-05-25"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "91310114607545250A"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0f:84:83:c4:c2:22:87:6d:d6:c6:ab:ed"
      )
}
