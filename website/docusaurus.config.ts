import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import type * as OpenApiPlugin from "docusaurus-plugin-openapi-docs";

const config: Config = {
  title: "Ory Talos",
  tagline: "High-performance cloud-native API key service",
  favicon: "img/favicon.ico",

  url: "https://www.ory.com",
  baseUrl: "/",

  organizationName: "aeneasr",
  projectName: "Ory Talos",

  onBrokenLinks: "throw",
  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: "throw",
    },
  },

  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },

  presets: [
    [
      "classic",
      {
        docs: {
          path: "../docs",
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          docItemComponent: "@theme/ApiItem",
        },
        blog: false,
        theme: {
          customCss: "./src/css/custom.css",
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    function suppressMermaidWarning() {
      return {
        name: "suppress-mermaid-warning",
        configureWebpack() {
          return {
            ignoreWarnings: [
              {
                module: /vscode-languageserver-types/,
                message: /Critical dependency/,
              },
            ],
          };
        },
      };
    },
    [
      "docusaurus-plugin-openapi-docs",
      {
        id: "api",
        docsPluginId: "classic",
        config: {
          talos: {
            specPath: "../api/talos.openapi-v3.json",
            outputDir: "../docs/reference/api",
            infoTemplate: "./src/templates/openapi-info.hbs",
            sidebarOptions: {
              groupPathsBy: "tag",
            },
          } satisfies OpenApiPlugin.Options,
        },
      },
    ],
    [
      "@easyops-cn/docusaurus-search-local",
      {
        hashed: true,
        indexDocs: true,
        indexBlog: false,
        docsRouteBasePath: "/",
        docsDir: "../docs",
      },
    ],
  ],

  themes: ["docusaurus-theme-openapi-docs", "@docusaurus/theme-mermaid"],

  themeConfig: {
    colorMode: {
      defaultMode: "dark",
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: "Ory Talos",
      items: [
        {
          type: "docSidebar",
          sidebarId: "docsSidebar",
          position: "left",
          label: "Docs",
        },
        {
          to: "/reference/api/ory-talos-api",
          label: "API",
          position: "left",
        },
        {
          href: "https://github.com/ory/talos",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Get started",
          items: [
            { label: "Quickstart", to: "/quickstart" },
            { label: "Integrate", to: "/integrate" },
            { label: "Operate", to: "/operate" },
          ],
        },
        {
          title: "Reference",
          items: [
            { label: "API", to: "/reference/api/ory-talos-api" },
            { label: "Configuration", to: "/reference/config" },
          ],
        },
        {
          title: "More",
          items: [{ label: "GitHub", href: "https://github.com/ory/talos" }],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Ory Corp. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.vsDark,
      additionalLanguages: ["bash", "go", "json", "protobuf", "yaml", "http"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
