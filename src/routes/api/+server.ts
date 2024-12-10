import { SECRET_API_KEY } from '$env/static/private';
import { json, type RequestHandler } from '@sveltejs/kit';

type CVE = {
	id: string;
	descriptions: {
		value: string;
		lang: string;
	}[];
	metrics?: {
		cvssMetricV2?: {
			baseSeverity: string;
		}[];
	};
	published: string;
};

type NVDResponse = {
	vulnerabilities: {
		cve: CVE;
	}[];
};

type SimplifiedVulnerability = {
	cveId: string;
	description: string;
	severity: string;
	publishedDate: string;
};

export const GET: RequestHandler = async () => {
	const apiKey = SECRET_API_KEY;
	const packageName = 'typescript';
	const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keyword=${packageName}`;

	try {
		const response = await fetch(url, {
			headers: {
				apiKey: apiKey,
			},
		});

		if (!response.ok) {
			return json(
				{ error: 'Failed to fetch vulnerability data' },
				{ status: response.status },
			);
		}

		const data: NVDResponse = await response.json();

		const vulnerabilities: SimplifiedVulnerability[] =
			data.vulnerabilities.map((vul) => ({
				cveId: vul.cve.id,
				description:
					vul.cve.descriptions[0].value || 'No description available',
				severity: vul.cve.metrics?.cvssMetricV2?.[0].baseSeverity || 'Unknown',
				publishedDate: vul.cve.published,
			})) || [];

		return json({ vulnerabilities });
	} catch (error) {
		console.error('Error fetching vulnerability data:', error);
		return json({ error: 'Something went wrong' }, { status: 500 });
	}
};
