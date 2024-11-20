export const saveCSV = jest.fn(() => {
  return { url: 'http://mock_url' };
});
export const listReports = jest.fn(() => ({ Contents: 'report content' }));
export const exportReport = jest.fn(() => 'report_url');

export default jest.fn(() => ({
  saveCSV,
  listReports,
  exportReport
}));
