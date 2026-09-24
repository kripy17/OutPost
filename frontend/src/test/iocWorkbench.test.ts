// Unit tests for IOC Workbench: defang, refang, indicator extraction, and RFC1918 classification

import { describe, expect, it } from "vitest";
import { defangText, extractIndicators, isPrivateIpv4, refangText } from "../components/IocWorkbench";

describe("IOC Workbench Defanging & Refanging", () => {
  it("refangs defanged URLs, domains, and emails", () => {
    expect(refangText("hxxps[://]evil[.]com/malware[.]bin")).toBe("https://evil.com/malware.bin");
    expect(refangText("hxxp[://]192[.]168[.]1[.]1[:]8080")).toBe("http://192.168.1.1:8080");
    expect(refangText("phish-alert[@]evil-domain[.]xyz")).toBe("phish-alert@evil-domain.xyz");
  });

  it("defangs standard URLs, domains, and emails", () => {
    expect(defangText("https://evil.com")).toBe("hxxps://evil[.]com");
    expect(defangText("http://c2.xyz/agent.exe")).toBe("hxxp://c2[.]xyz/agent[.]exe");
    expect(defangText("admin@bad.net")).toBe("admin[@]bad[.]net");
  });
});

describe("isPrivateIpv4", () => {
  it("detects RFC1918 private and loopback addresses", () => {
    expect(isPrivateIpv4("10.0.4.15")).toBe(true);
    expect(isPrivateIpv4("172.16.5.99")).toBe(true);
    expect(isPrivateIpv4("192.168.1.1")).toBe(true);
    expect(isPrivateIpv4("127.0.0.1")).toBe(true);
  });

  it("identifies public routable IPv4 addresses", () => {
    expect(isPrivateIpv4("198.51.100.44")).toBe(false);
    expect(isPrivateIpv4("8.8.8.8")).toBe(false);
    expect(isPrivateIpv4("203.0.113.195")).toBe(false);
  });
});

describe("extractIndicators", () => {
  it("extracts all indicator types from unstructured text", () => {
    const text = `
      Incident Advisory:
      Observed C2 communicating at hxxps[://]beacon-c2[.]com/payload[.]exe
      Staging server IP: 198[.]51[.]100[.]44
      Internal pivoting: 10.0.0.15 and 192.168.1.1
      Phishing contact: attacker[@]evil-portal[.]xyz
      Hashes:
      MD5: e4d909c290d0fb1ca068ffaddf22cbd0
      SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    `;

    const indicators = extractIndicators(text);
    expect(indicators.length).toBeGreaterThanOrEqual(6);

    const types = indicators.map((i) => i.type);
    expect(types).toContain("url");
    expect(types).toContain("ip");
    expect(types).toContain("email");
    expect(types).toContain("hash");

    const urlInd = indicators.find((i) => i.type === "url");
    expect(urlInd?.refanged).toBe("https://beacon-c2.com/payload.exe");

    const privIp = indicators.find((i) => i.refanged === "10.0.0.15");
    expect(privIp?.isPrivate).toBe(true);

    const pubIp = indicators.find((i) => i.refanged === "198.51.100.44");
    expect(pubIp?.isPrivate).toBe(false);

    const sha = indicators.find((i) => i.subType === "sha256");
    expect(sha?.refanged).toBe("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
  });

  it("handles empty or whitespace-only input safely", () => {
    expect(extractIndicators("")).toEqual([]);
    expect(extractIndicators("   \n\t  ")).toEqual([]);
  });
});
