import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";
import apiSidebar from "../docs/reference/api/sidebar";

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: "doc",
      id: "index",
      label: "Home",
    },
    {
      type: "category",
      label: "Quickstarts",
      collapsed: false,
      items: [
        { type: "doc", id: "quickstart/open-source", label: "Open source" },
        {
          type: "doc",
          id: "quickstart/docker-commercial",
          label: "Enterprise",
        },
      ],
    },
    {
      type: "category",
      label: "Integrate",
      collapsed: false,
      link: { type: "doc", id: "integrate/index" },
      items: [
        "integrate/issue-and-verify",
        "integrate/import-keys",
        "integrate/derive-tokens",
        "integrate/batch-operations",
        "integrate/key-lifecycle",
        "integrate/self-revocation",
        "integrate/ip-restrictions",
        "integrate/rate-limiting",
        "integrate/error-handling",
        {
          type: "category",
          label: "SDK",
          items: ["integrate/sdk/go", "integrate/sdk/curl"],
        },
      ],
    },
    {
      type: "category",
      label: "Operate",
      collapsed: false,
      link: { type: "doc", id: "operate/index" },
      items: [
        "operate/install",
        "operate/configure",
        {
          type: "category",
          label: "Database",
          link: { type: "doc", id: "operate/database/index" },
          items: [
            "operate/database/sqlite",
            "operate/database/postgresql",
            "operate/database/mysql",
            "operate/database/cockroachdb",
            "operate/database/migrations",
          ],
        },
        {
          type: "category",
          label: "Deploy",
          link: { type: "doc", id: "operate/deploy/index" },
          items: [
            "operate/deploy/docker",
            "operate/deploy/deployment-modes",
            "operate/deploy/edge-proxy",
          ],
        },
        "operate/secrets",
        "operate/tls",
        {
          type: "category",
          label: "Monitoring",
          link: { type: "doc", id: "operate/monitoring/index" },
          items: [
            "operate/monitoring/metrics",
            "operate/monitoring/tracing",
            "operate/monitoring/health-checks",
          ],
        },
        {
          type: "category",
          label: "Cache",
          link: { type: "doc", id: "operate/cache/index" },
          items: ["operate/cache/memory", "operate/cache/redis"],
        },
        "operate/multi-tenancy",
        "operate/troubleshooting",
        "operate/security-hardening",
      ],
    },
    {
      type: "category",
      label: "Concepts",
      collapsed: true,
      link: { type: "doc", id: "concepts/index" },
      items: [
        "concepts/architecture",
        "concepts/credential-types",
        "concepts/token-format",
        "concepts/security-model",
        "concepts/caching",
        "concepts/rate-limiting",
      ],
    },
    {
      type: "category",
      label: "Reference",
      collapsed: true,
      link: { type: "doc", id: "reference/index" },
      items: [
        {
          type: "category",
          label: "API",
          link: { type: "doc", id: "reference/api/ory-talos-api" },
          items: apiSidebar,
        },
        "reference/config",
        "reference/error-codes",
        "reference/token-format",
      ],
    },
  ],
};

export default sidebars;
