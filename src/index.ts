import { Router, Request, Response, json } from 'express';
import { JavaScriptSecurityAnalyzer, SecurityAnalysisResult } from './util';

const ID = 'js-security';

async function init(router: Router): Promise<void> {
  // Security analysis endpoint
  // @ts-ignore
  router.post('/analyze', (request: Request, response: Response) => {
    try {
      const { code, settings } = request.body;

      if (!code || typeof code !== 'string') {
        return response.status(400).json({
          error: 'Missing or invalid "code" parameter. Expected a string.',
        });
      }

      const analyzer = new JavaScriptSecurityAnalyzer();

      // Update analyzer settings if provided
      if (settings && typeof settings === 'object') {
        analyzer.updateSettings(settings);
      }

      // Analyze the JavaScript code
      const result: SecurityAnalysisResult = analyzer.analyzeScript(code);

      return response.json(result);
    } catch (error) {
      console.error('Error analyzing JavaScript code:', error);
      return response.status(500).json({
        error: 'Internal server error during analysis',
        details: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  });
}

interface PluginInfo {
  id: string;
  name: string;
  description: string;
}

export default {
  init,
  exit: (): void => {},
  info: {
    id: ID,
    name: 'JS Security',
    description: 'Utility endpoint for JS Security plugin',
  } as PluginInfo,
};
