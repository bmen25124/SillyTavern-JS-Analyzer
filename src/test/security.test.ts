import { JavaScriptSecurityAnalyzer } from '../util';

describe('JavaScriptSecurityAnalyzer', () => {
  let analyzer: JavaScriptSecurityAnalyzer;

  beforeEach(() => {
    analyzer = new JavaScriptSecurityAnalyzer();
  });

  describe('Safe JavaScript Code', () => {
    test('should allow simple console logging', () => {
      const code = `console.log('Hello, world!');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
      expect(result.sanitizedCode).toBe(code);
    });

    test('should allow safe DOM manipulation', () => {
      const code = `
        const element = document.getElementById('myDiv');
        if (element) {
          element.style.color = 'red';
          element.textContent = 'Updated text';
        }
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    test('should allow Math operations', () => {
      const code = `
        const randomNum = Math.random();
        const result = Math.floor(randomNum * 100);
        console.log('Random number:', result);
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    test('should allow Date operations', () => {
      const code = `
        const now = new Date();
        const timestamp = now.getTime();
        console.log('Current time:', now.toISOString());
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    test('should allow JSON operations', () => {
      const code = `
        const data = { name: 'test', value: 42 };
        const jsonString = JSON.stringify(data);
        const parsed = JSON.parse(jsonString);
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });

  describe('Dangerous JavaScript Code', () => {
    test('should block fetch API calls', () => {
      const code = `fetch('/api/data');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('dangerous_api_call');
      expect(result.violations[0].node).toBe('fetch');
      expect(result.violations[0].severity).toBe('error');
    });

    test('should block XMLHttpRequest usage', () => {
      const code = `
        const xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/data');
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations.some((v) => v.node === 'XMLHttpRequest')).toBe(true);
    });

    test('should block eval usage', () => {
      const code = `eval('malicious code');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(2); // One for dangerous API, one for dynamic evaluation
      expect(result.violations.some((v) => v.type === 'dangerous_api_call')).toBe(true);
      expect(result.violations.some((v) => v.type === 'dynamic_evaluation')).toBe(true);
    });

    test('should block Function constructor', () => {
      const code = `new Function('return 1 + 1')();`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations.some((v) => v.node === 'Function')).toBe(true);
    });

    test('should block localStorage access', () => {
      const code = `localStorage.setItem('key', 'value');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('dangerous_api_call');
      expect(result.violations[0].node).toBe('localStorage.setItem');
    });

    test('should block sessionStorage access', () => {
      const code = `const data = sessionStorage.getItem('key');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('dangerous_api_call');
    });

    test('should block window.location manipulation', () => {
      const code = `window.location = 'http://evil.com';`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations.some((v) => v.type === 'dangerous_assignment')).toBe(true);
    });

    test('should block document.cookie access', () => {
      const code = `document.cookie = 'session=stolen';`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations.some((v) => v.type === 'dangerous_assignment')).toBe(true);
    });

    test('should block WebSocket creation', () => {
      const code = `const ws = new WebSocket('ws://evil.com');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('dangerous_constructor');
      expect(result.violations[0].node).toBe('WebSocket');
    });
  });

  describe('Obfuscation Detection', () => {
    test('should detect hex encoding obfuscation', () => {
      const code = `const str = '\\x48\\x65\\x6c\\x6c\\x6f';`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.some((v) => v.type === 'obfuscation_detected')).toBe(true);
    });

    test('should detect unicode encoding obfuscation', () => {
      const code = `const str = '\\u0048\\u0065\\u006c\\u006c\\u006f';`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.some((v) => v.type === 'obfuscation_detected')).toBe(true);
    });

    test('should detect String.fromCharCode obfuscation', () => {
      const code = `const str = String.fromCharCode(72, 101, 108, 108, 111);`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.some((v) => v.type === 'obfuscation_detected')).toBe(true);
    });

    test('should detect base64 encoding/decoding', () => {
      const code = `const decoded = atob('SGVsbG8gV29ybGQ=');`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.some((v) => v.type === 'obfuscation_detected')).toBe(true);
    });

    test('should allow obfuscation when configured', () => {
      const analyzerWithObfuscation = new JavaScriptSecurityAnalyzer({
        allowObfuscation: true,
      });
      const code = `const str = '\\x48\\x65\\x6c\\x6c\\x6f';`;
      const result = analyzerWithObfuscation.analyzeScript(code);

      expect(result.violations.some((v) => v.type === 'obfuscation_detected')).toBe(false);
    });
  });

  describe('Script Size Limits', () => {
    test('should block scripts exceeding size limit', () => {
      const analyzerWithSmallLimit = new JavaScriptSecurityAnalyzer({
        maxScriptLength: 10,
      });
      const code = `console.log('This script is too long for the limit');`;
      const result = analyzerWithSmallLimit.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('script_too_large');
    });

    test('should allow scripts within size limit', () => {
      const analyzerWithLargeLimit = new JavaScriptSecurityAnalyzer({
        maxScriptLength: 1000,
      });
      const code = `console.log('Short script');`;
      const result = analyzerWithLargeLimit.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations.filter((v) => v.type === 'script_too_large')).toHaveLength(0);
    });
  });

  describe('Configuration Options', () => {
    test('should respect disabled analysis', () => {
      const disabledAnalyzer = new JavaScriptSecurityAnalyzer({
        enableJSAnalysis: false,
      });
      const code = `fetch('/dangerous/url'); eval('bad code');`;
      const result = disabledAnalyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
      expect(result.sanitizedCode).toBe(code);
    });

    test('should respect custom blocked APIs', () => {
      const customAnalyzer = new JavaScriptSecurityAnalyzer({
        blockedAPIs: ['customAPI', 'anotherDangerousFunction'],
      });
      const code = `customAPI(); console.log('safe');`;
      const result = customAnalyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.some((v) => v.node === 'customAPI')).toBe(true);
    });

    test('should update settings dynamically', () => {
      const code = `fetch('/api/data');`;

      // Initially should block fetch
      let result = analyzer.analyzeScript(code);
      expect(result.safe).toBe(false);

      // Update settings to disable analysis
      analyzer.updateSettings({ enableJSAnalysis: false });
      result = analyzer.analyzeScript(code);
      expect(result.safe).toBe(true);
    });
  });

  describe('Code Sanitization', () => {
    test('should sanitize dangerous code', () => {
      const code = `
        console.log('Safe code');
        fetch('/dangerous/url');
        console.log('More safe code');
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.sanitizedCode).toContain('/* fetch() blocked for security */');
      expect(result.sanitizedCode).toContain('console.log');
    });

    test('should handle multiple violations in sanitization', () => {
      const code = `
        fetch('/url1');
        eval('code');
        localStorage.getItem('key');
      `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations.length).toBeGreaterThan(1);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid JavaScript syntax', () => {
      const code = `invalid javascript syntax { { {`;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].type).toBe('parse_error');
    });

    test('should handle empty scripts', () => {
      const code = ``;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    test('should handle whitespace-only scripts', () => {
      const code = `   \n\t  `;
      const result = analyzer.analyzeScript(code);

      expect(result.safe).toBe(true);
      expect(result.violations).toHaveLength(0);
    });
  });
});
