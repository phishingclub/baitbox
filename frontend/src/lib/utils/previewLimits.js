// Limits for package preview images. The server enforces the same values
// (service/previewimage.go); checking here saves uploading a file it rejects.
const PREVIEW_MAX_BYTES = 2 * 1024 * 1024;
const PREVIEW_MAX_SIDE = 4096;
export const PREVIEW_ACCEPT = 'image/png,image/jpeg,image/gif,image/webp';
export const PREVIEW_LIMITS_TEXT = `PNG, JPEG, GIF or WebP, up to 2 MB and ${PREVIEW_MAX_SIDE}×${PREVIEW_MAX_SIDE} pixels each.`;

// previewFileProblem returns why a picked file cannot be a preview, or ''.
export function previewFileProblem(file) {
	if (!PREVIEW_ACCEPT.split(',').includes(file.type)) return `${file.name} is not a PNG, JPEG, GIF or WebP image`;
	if (file.size > PREVIEW_MAX_BYTES) return `${file.name} is larger than 2 MB`;
	return '';
}
