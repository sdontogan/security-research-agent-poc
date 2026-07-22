export const siteConfig = {
  title: 'Beyond Features',
  owner: 'Sarah D',
  description:
    'Portfolio of Sarah D, a senior data scientist building production AI across enterprise learning, knowledge systems, and cybersecurity.',
  domain: 'beyond-features.com',
  url: 'https://beyond-features.com',
  linkedin: 'https://www.linkedin.com/in/sarah-dontogan-29797483/',
  github: 'https://github.com/sdontogan',
  resumeUrl: '/Sarah_D_Resume_2026.pdf',
  resumeDownloadUrl: '/Sarah_D_Resume_2026.docx',
  currentRole: 'Senior Data Scientist',
  // EDIT ME: Replace when you want to publish a location.
  location: '[LOCATION]',
  // EDIT ME: Replace with a public job-search or consulting status.
  availability: '[AVAILABILITY_STATUS]',
} as const;

export const targetRoles = [
  'Senior Data Scientist',
  'Senior Machine Learning Engineer',
  'Applied AI Engineer',
] as const;

export const navigation = [
  { label: 'Home', href: '/' },
  { label: 'About Me', href: '/about' },
  { label: 'Projects', href: '/projects' },
  { label: 'Writing', href: '/writing' },
  { label: 'Résumé', href: '/resume' },
  { label: 'Contact', href: '/contact' },
] as const;
