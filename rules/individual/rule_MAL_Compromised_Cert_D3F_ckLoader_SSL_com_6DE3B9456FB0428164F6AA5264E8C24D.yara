import "pe"

rule MAL_Compromised_Cert_D3F_ckLoader_SSL_com_6DE3B9456FB0428164F6AA5264E8C24D {
   meta:
      description         = "Detects D3F@ckLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-15"
      version             = "1.0"

      hash                = "e257cf8c1fc5332bf81f85408123762457a698709f745da15607dc594742019f"
      malware             = "D3F@ckLoader"
      malware_type        = "Loader"
      malware_notes       = "This malware as sold was part of a service: it included both the loader and a code-signing certificate. See this for more details: https://www.esentire.com/blog/exploring-the-d3f-ck-malware-as-a-service-loader"

      signer              = "Dawood It Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6d:e3:b9:45:6f:b0:42:81:64:f6:aa:52:64:e8:c2:4d"
      cert_thumbprint     = "CE30FAED4BB6BA0440970E7F3F341EAE3DA98806"
      cert_valid_from     = "2024-04-15"
      cert_valid_to       = "2025-04-15"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "08765659"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6d:e3:b9:45:6f:b0:42:81:64:f6:aa:52:64:e8:c2:4d"
      )
}
