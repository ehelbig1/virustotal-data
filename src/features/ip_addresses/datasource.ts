import axios from 'axios';

import { GetIpInfoResponse } from './models/get_ip_info';

export interface IVirusTotalIpAddressDatasource {
    getIpInfo: (ip: string) => Promise<GetIpInfoResponse>;
}

export class VirusTotalIpAddressDatasource implements IVirusTotalIpAddressDatasource {
    baseUrl = 'https://www.virustotal.com/api';
    apiKey: string;

    constructor() {
        if (process.env.VIRUSTOTAL_API_KEY) {
            this.apiKey = process.env.VIRUSTOTAL_API_KEY;
        } else {
            throw new Error('Must provide VIRUSTOTAL_API_KEY environmental varialble');
        }
    }

    async getIpInfo(ip: string): Promise<GetIpInfoResponse> {
        try {
            const response = await axios.get<GetIpInfoResponse>(`${this.baseUrl}/v3/ip_addresses/${ip}`, {
                headers: {
                    'x-apikey': this.apiKey,
                },
            });

            const ipInfo: GetIpInfoResponse = response.data;

            return ipInfo;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                throw error.message;
            } else {
                throw new Error(`Oops, something went wrong\n${error}`);
            }
        }
    }
}
