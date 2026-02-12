const NAV = [
  {
    section: "Start Here",
    pages: [
      ["Home", "Home"],
      ["Get Started", "Get-Started"],
      ["Overview", "Overview"],
    ],
  },
  {
    section: "Concepts",
    pages: [
      ["Architecture and Data Model", "Architecture-and-Data-Model"],
      ["Tokens and Keys", "Tokens-and-Keys"],
      ["Multi-Tenant Authorization", "Multi-Tenant-Authorization"],
      ["Security Model", "Security-Model"],
    ],
  },
  {
    section: "API and Integration",
    pages: [
      ["API Specification", "API-Specification"],
      ["codeQ Integration", "codeQ-Integration"],
    ],
  },
  {
    section: "Use Cases",
    pages: [
      ["Use Cases", "Use-Cases"],
      ["Use Case: OOB Email Sign-In", "Use-Cases-OOB-Email-Sign-In"],
      ["Use Case: Password Sign-In", "Use-Cases-Password-Sign-In"],
      ["Use Case: codeQ Worker Token Exchange", "Use-Cases-codeQ-Worker-Token-Exchange"],
      ["Use Case: Tenant Admin Lifecycle", "Use-Cases-Tenant-Admin-Lifecycle"],
      ["Use Case: Resource Server Token Validation", "Use-Cases-Resource-Server-Token-Validation"],
    ],
  },
  {
    section: "Operations",
    pages: [
      ["Operations and SLO", "Operations-and-SLO"],
      ["Troubleshooting", "Troubleshooting"],
      ["Release and Compatibility", "Release-and-Compatibility"],
    ],
  },
  {
    section: "Tooling and Tests",
    pages: [
      ["CLI Reference", "CLI-Reference"],
      ["Unit Test Functional Matrix", "Unit-Test-Functional-Matrix"],
      ["Unit Test Execution Backlog", "Unit-Test-Execution-Backlog"],
    ],
  },
];

const DEFAULT_PAGE = "Home";
const navEl = document.getElementById("nav");
const contentEl = document.getElementById("content");
const searchEl = document.getElementById("search");
const currentPageEl = document.getElementById("current-page");

const ALL_PAGE_SLUGS = NAV.flatMap((group) => group.pages.map((p) => p[1]));

function getPageFromUrl() {
  const page = new URLSearchParams(window.location.search).get("page");
  if (page && ALL_PAGE_SLUGS.includes(page)) {
    return page;
  }
  return DEFAULT_PAGE;
}

function pageLabel(slug) {
  for (const group of NAV) {
    const found = group.pages.find((entry) => entry[1] === slug);
    if (found) {
      return found[0];
    }
  }
  return slug.replaceAll("-", " ");
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function rewriteInternalLinks() {
  const anchors = contentEl.querySelectorAll("a[href]");
  for (const a of anchors) {
    const href = a.getAttribute("href") || "";
    if (!href) {
      continue;
    }
    if (
      href.startsWith("http://") ||
      href.startsWith("https://") ||
      href.startsWith("mailto:") ||
      href.startsWith("#") ||
      href.startsWith("/")
    ) {
      continue;
    }
    const clean = href.replace(/^\.\//, "").replace(/\.md$/, "").replace(/\/$/, "");
    if (!ALL_PAGE_SLUGS.includes(clean)) {
      continue;
    }
    a.setAttribute("href", `?page=${encodeURIComponent(clean)}`);
  }
}

function renderNavigation(activePage, filterText = "") {
  const normalizedFilter = filterText.trim().toLowerCase();
  navEl.innerHTML = "";

  for (const group of NAV) {
    const filteredPages = group.pages.filter((entry) => {
      if (!normalizedFilter) {
        return true;
      }
      return entry[0].toLowerCase().includes(normalizedFilter);
    });

    if (!filteredPages.length) {
      continue;
    }

    const groupWrap = document.createElement("section");
    groupWrap.className = "nav-group";

    const title = document.createElement("h3");
    title.className = "nav-title";
    title.textContent = group.section;
    groupWrap.appendChild(title);

    const list = document.createElement("ul");
    list.className = "nav-list";

    for (const [label, slug] of filteredPages) {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = `?page=${encodeURIComponent(slug)}`;
      link.textContent = label;
      link.className = `nav-link${slug === activePage ? " active" : ""}`;
      li.appendChild(link);
      list.appendChild(li);
    }

    groupWrap.appendChild(list);
    navEl.appendChild(groupWrap);
  }
}

function prepareMarkdown(markdownText) {
  return markdownText.replace(/```mermaid\s*\n([\s\S]*?)```/g, (_, code) => {
    return `<div class="mermaid">${escapeHtml(code.trim())}</div>`;
  });
}

async function renderMermaid() {
  const blocks = contentEl.querySelectorAll(".mermaid");
  if (!blocks.length) {
    return;
  }
  try {
    mermaid.initialize({
      startOnLoad: false,
      theme: "dark",
      securityLevel: "loose",
      fontFamily: "Space Grotesk, sans-serif",
    });
    await mermaid.run({ nodes: blocks });
  } catch (error) {
    console.error("Mermaid render error:", error);
  }
}

async function loadPage(pageSlug) {
  currentPageEl.textContent = pageLabel(pageSlug);
  document.title = `${pageLabel(pageSlug)} | Tikti Wiki`;
  renderNavigation(pageSlug, searchEl.value);

  try {
    const response = await fetch(`${pageSlug}.md`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Unable to load page ${pageSlug} (status ${response.status})`);
    }

    const markdown = await response.text();
    const prepared = prepareMarkdown(markdown);
    contentEl.innerHTML = marked.parse(prepared);
    rewriteInternalLinks();
    await renderMermaid();
  } catch (error) {
    contentEl.innerHTML = `
      <div class="error-card">
        <strong>Could not load this page.</strong><br>
        ${escapeHtml(error.message)}
      </div>
    `;
  }
}

window.addEventListener("popstate", () => {
  loadPage(getPageFromUrl());
});

document.addEventListener("click", (event) => {
  const target = event.target.closest("a[href]");
  if (!target) {
    return;
  }

  const href = target.getAttribute("href") || "";
  if (!href.startsWith("?page=")) {
    return;
  }

  event.preventDefault();
  const url = new URL(href, window.location.href);
  const page = url.searchParams.get("page");
  if (!page || !ALL_PAGE_SLUGS.includes(page)) {
    return;
  }
  history.pushState({}, "", `?page=${encodeURIComponent(page)}`);
  loadPage(page);
});

searchEl.addEventListener("input", () => {
  renderNavigation(getPageFromUrl(), searchEl.value);
});

loadPage(getPageFromUrl());
