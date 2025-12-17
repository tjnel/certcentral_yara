import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_4994AC1FB0662DADE0F5759A {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-04"
      version             = "1.0"

      hash                = "b97cd404ceab09bdd92003599566d946cead1d5d5dba528327821fe4f18108ec"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Jupiter"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:94:ac:1f:b0:66:2d:ad:e0:f5:75:9a"
      cert_thumbprint     = "94E8399C43C6F0D9DF5DCF205872D575825F7B92"
      cert_valid_from     = "2025-07-04"
      cert_valid_to       = "2026-07-05"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "5167746260369"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:94:ac:1f:b0:66:2d:ad:e0:f5:75:9a"
      )
}
