export const RECON_TOOLS_SCHEMA = [
  {
    type: "function",
    function: {
      name: "get_apex_dns",
      description: "Ambil DNS record utama (NS, MX, TXT/SPF/DMARC, SOA) dan deteksi apakah Wildcard DNS aktif pada domain.",
      parameters: {
        type: "object",
        properties: {
          domain: {
            type: "string",
            description: "Apex domain target, misal: example.com",
          },
        },
        required: ["domain"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "discover_subdomains_ct",
      description: "Ambil daftar seluruh subdomain historis dan aktif menggunakan Certificate Transparency (CT) logs (crt.sh).",
      parameters: {
        type: "object",
        properties: {
          domain: {
            type: "string",
            description: "Apex domain target untuk dicari riwayat sertifikatnya.",
          },
        },
        required: ["domain"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "resolve_subdomain_batch",
      description: "Resolving DNS secara paralel untuk mendeteksi IP aktif dan CNAME cloud (AWS, Azure, CloudFront, dll).",
      parameters: {
        type: "object",
        properties: {
          subdomains: {
            type: "array",
            items: { type: "string" },
            description: "List FQDN subdomain yang akan di-resolve (maksimal 60 per batch).",
          },
        },
        required: ["subdomains"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "probe_http_batch",
      description: "Probe status HTTP/HTTPS, title halaman, banner server, tech stack, dan anomali pada host aktif.",
      parameters: {
        type: "object",
        properties: {
          hosts: {
            type: "array",
            items: { type: "string" },
            description: "List FQDN host aktif untuk di-probe HTTP/HTTPS (maksimal 30 per batch).",
          },
        },
        required: ["hosts"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "inspect_takeover_risk",
      description: "Analisis mendalam pointer CNAME eksternal yang mencurigakan (S3 NoSuchBucket, dsb) untuk verifikasi risiko takeover.",
      parameters: {
        type: "object",
        properties: {
          fqdn: {
            type: "string",
            description: "Subdomain target yang memiliki CNAME eksternal.",
          },
          cname: {
            type: "string",
            description: "Alamat CNAME tujuan, misal: mybucket.s3.amazonaws.com",
          },
        },
        required: ["fqdn", "cname"],
      },
    },
  },
];
