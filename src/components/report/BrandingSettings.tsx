import { useState, useRef } from 'react';
import { Upload, Image, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import type { ReportBranding } from '@/lib/pdfReportGenerator';

interface BrandingSettingsProps {
  branding: Partial<ReportBranding>;
  onChange: (branding: Partial<ReportBranding>) => void;
}

export function BrandingSettings({ branding, onChange }: BrandingSettingsProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [previewUrl, setPreviewUrl] = useState<string | undefined>(branding.logoDataUrl);

  const handleLogoUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      setPreviewUrl(dataUrl);
      onChange({ ...branding, logoDataUrl: dataUrl });
    };
    reader.readAsDataURL(file);
  };

  const removeLogo = () => {
    setPreviewUrl(undefined);
    onChange({ ...branding, logoDataUrl: undefined });
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label>Company Logo</Label>
        <div className="flex items-center gap-4">
          {previewUrl ? (
            <div className="relative">
              <Card className="p-2 bg-muted/50">
                <img src={previewUrl} alt="Logo preview" className="h-16 w-auto object-contain" />
              </Card>
              <Button
                size="icon"
                variant="destructive"
                className="absolute -top-2 -right-2 h-6 w-6"
                onClick={removeLogo}
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          ) : (
            <Card 
              className="h-20 w-32 border-dashed border-2 flex items-center justify-center cursor-pointer hover:bg-muted/50 transition-colors"
              onClick={() => fileInputRef.current?.click()}
            >
              <div className="text-center">
                <Image className="w-6 h-6 mx-auto text-muted-foreground" />
                <span className="text-xs text-muted-foreground">Upload logo</span>
              </div>
            </Card>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            className="hidden"
            onChange={handleLogoUpload}
          />
          {!previewUrl && (
            <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
              <Upload className="w-4 h-4 mr-2" />
              Choose File
            </Button>
          )}
        </div>
        <p className="text-xs text-muted-foreground">Recommended: 200x200px PNG or JPG</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="companyName">Company Name</Label>
        <Input
          id="companyName"
          value={branding.companyName || ''}
          onChange={(e) => onChange({ ...branding, companyName: e.target.value })}
          placeholder="Your Company Name"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="primaryColor">Primary Color</Label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              id="primaryColor"
              value={branding.primaryColor || '#3b82f6'}
              onChange={(e) => onChange({ ...branding, primaryColor: e.target.value })}
              className="h-10 w-14 rounded border border-input cursor-pointer"
            />
            <Input
              value={branding.primaryColor || '#3b82f6'}
              onChange={(e) => onChange({ ...branding, primaryColor: e.target.value })}
              className="flex-1"
              placeholder="#3b82f6"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="secondaryColor">Secondary Color</Label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              id="secondaryColor"
              value={branding.secondaryColor || '#1e40af'}
              onChange={(e) => onChange({ ...branding, secondaryColor: e.target.value })}
              className="h-10 w-14 rounded border border-input cursor-pointer"
            />
            <Input
              value={branding.secondaryColor || '#1e40af'}
              onChange={(e) => onChange({ ...branding, secondaryColor: e.target.value })}
              className="flex-1"
              placeholder="#1e40af"
            />
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="footerText">Footer Text</Label>
        <Input
          id="footerText"
          value={branding.footerText || ''}
          onChange={(e) => onChange({ ...branding, footerText: e.target.value })}
          placeholder="Confidential - For Internal Use Only"
        />
      </div>

      {/* Preview */}
      <Card className="p-4 bg-gradient-to-r from-muted/50 to-muted/30">
        <p className="text-xs text-muted-foreground mb-2">Preview</p>
        <div 
          className="h-8 rounded flex items-center px-3 gap-2"
          style={{ backgroundColor: branding.primaryColor || '#3b82f6' }}
        >
          {previewUrl && (
            <img src={previewUrl} alt="Logo" className="h-5 w-auto" />
          )}
          <span className="text-white text-sm font-medium">
            {branding.companyName || 'Your Company Name'}
          </span>
        </div>
      </Card>
    </div>
  );
}
