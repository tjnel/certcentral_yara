import "pe"

rule MAL_Compromised_Cert_Donut_Sectigo_77344A8C067A2B9BB97938F227B7D39F {
   meta:
      description         = "Detects Donut with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-20"
      version             = "1.0"

      hash                = "a36c0f2d5f32bd3831ec6336820d08c2865a2be3c25a7f3bd599ec9017f19b7d"
      malware             = "Donut"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "55.604.504 Rafael Ferreira de Carvalho"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "77:34:4a:8c:06:7a:2b:9b:b9:79:38:f2:27:b7:d3:9f"
      cert_thumbprint     = "BBED9DEAE08E2CD1302C6A8D98325BC4441066AF"
      cert_valid_from     = "2025-02-20"
      cert_valid_to       = "2025-10-30"

      country             = "BR"
      state               = "Distrito Federal"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "55.604.504/0001-02"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "77:34:4a:8c:06:7a:2b:9b:b9:79:38:f2:27:b7:d3:9f"
      )
}
