// crawler.js
import { CheerioCrawler } from 'crawlee';
import fs from 'fs';

const target = process.argv[2];
if (!target) {
    console.error("❌ Please provide a target domain (e.g. https://example.com)");
    process.exit(1);
}

const outFile = `output_${new URL(target).hostname}.txt`;
const outputStream = fs.createWriteStream(outFile);

const crawler = new CheerioCrawler({
    async requestHandler({ request, $, enqueueLinks }) {
        console.log(`🕷 Crawling: ${request.url}`);
        outputStream.write(request.url + "\n");
        await enqueueLinks({ strategy: 'same-origin' });
    },
});

await crawler.run([target]);

outputStream.end(() => {
    console.log(`✅ Done. Output saved to ${outFile}`);
});
