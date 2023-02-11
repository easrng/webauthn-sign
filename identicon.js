/* global base64js */
(function () {
  const Identicon = function (hash, options) {
    this.hashReady = crypto.subtle.digest("SHA-256", hash).then((buf) => {
      if (!(buf instanceof Uint8Array)) {
        buf = new Uint8Array(buf);
      }
      this.hash = [...buf]
        .map(x => x.toString(16).padStart(2, "0"))
        .join("");
    });

    this.defaults = {
      background: [0, 0, 0, 0],
      margin: 0,
      size: 20,
      saturation: 0.7,
      brightness: 0.5,
    };

    this.options = typeof options === "object" ? options : this.defaults;

    // backward compatibility with old constructor (hash, size, margin)
    if (typeof arguments[1] === "number") {
      this.options.size = arguments[1];
    }
    if (arguments[2]) {
      this.options.margin = arguments[2];
    }
    this.background = this.options.background || this.defaults.background;
    this.size = this.options.size || this.defaults.size;
    this.margin =
      this.options.margin !== undefined
        ? this.options.margin
        : this.defaults.margin;

    // foreground defaults to last 7 chars as hue at 70% saturation, 50% brightness
    this.hashReady.then(()=>{
    var hue = parseInt(this.hash.slice(15, 22), 16) / 0xfffffff;
    var saturation = this.options.saturation || this.defaults.saturation;
    var brightness = this.options.brightness || this.defaults.brightness;
    this.foreground =
      this.options.foreground || this.hsl2rgb(hue, saturation, brightness);
    })
  };
  Identicon.prototype = {
    background: null,
    foreground: null,
    hash: null,
    margin: null,
    size: null,

    image: function () {
      return new Svg(this.size, this.foreground, this.background);
    },

    render: async function () {
      await this.hashReady;
      var image = this.image(),
        size = this.size,
        baseMargin = Math.floor(size * this.margin),
        cell = Math.floor((size - baseMargin * 2) / 5),
        margin = Math.floor((size - cell * 5) / 2),
        bg = image.color.apply(image, this.background),
        fg = image.color.apply(image, this.foreground);
      image.cell = cell;
      let bits = this.hash
        .slice(22)
        .split("")
        .map((e) => parseInt(e, 16).toString(2).padStart(4, "0").split(""))
        .flat()
        .map((e) => e == "1");
      let biti = 0;
      image.getBit = function () {
        return bits[biti++ % bits.length];
      };

      // the first 15 characters of the hash control the pixels (even/odd)
      // they are drawn down the middle first, then mirrored outwards
      var i, color;
      for (i = 0; i < 15; i++) {
        color = parseInt(this.hash.charAt(i), 16) % 2 ? bg : fg;
        if (i < 5) {
          this.rectangle(
            2 * cell + margin,
            i * cell + margin,
            cell,
            cell,
            color,
            image
          );
        } else if (i < 10) {
          this.rectangle(
            1 * cell + margin,
            (i - 5) * cell + margin,
            cell,
            cell,
            color,
            image
          );
          this.rectangle(
            3 * cell + margin,
            (i - 5) * cell + margin,
            cell,
            cell,
            color,
            image
          );
        } else if (i < 15) {
          this.rectangle(
            0 * cell + margin,
            (i - 10) * cell + margin,
            cell,
            cell,
            color,
            image
          );
          this.rectangle(
            4 * cell + margin,
            (i - 10) * cell + margin,
            cell,
            cell,
            color,
            image
          );
        }
      }

      return image;
    },

    rectangle: function (x, y, w, h, color, image) {
      image.rectangles.push({ x: x, y: y, w: w, h: h, color: color });
    },

    // adapted from: https://gist.github.com/aemkei/1325937
    hsl2rgb: function (h, s, b) {
      h *= 6;
      s = [
        (b += s *= b < 0.5 ? b : 1 - b),
        b - (h % 1) * s * 2,
        (b -= s *= 2),
        b,
        b + (h % 1) * s,
        b + s,
      ];

      return [
        s[~~h % 6] * 255, // red
        s[(h | 16) % 6] * 255, // green
        s[(h | 8) % 6] * 255, // blue
      ];
    }
  };
  const Svg = function (size, foreground, background) {
    this.size = size;
    this.foreground = this.color.apply(this, foreground);
    this.background = this.color.apply(this, background);
    this.rectangles = [];
  };
  Svg.prototype = {
    size: null,
    foreground: null,
    background: null,
    rectangles: null,

    color: function (r, g, b, a) {
      var values = [r, g, b].map(Math.round);
      values.push(a >= 0 && a <= 255 ? a / 255 : 1);
      return "rgba(" + values.join(",") + ")";
    },

    getDump: function () {
      var i,
        xml,
        rect,
        fg = this.foreground,
        bg = this.background,
        stroke = 0;
      this.rectangles = this.rectangles
        .filter((rect) => rect.color != bg)
        .map(({ x, y, w, h }) => ({
          x,
          y,
          w,
          h,
          points: [
            x + "," + y,
            x + w + "," + y,
            x + w + "," + (y + h),
            x + "," + (y + h),
          ],
        }));
      const pointCounts = this.rectangles
        .map((e) => e.points)
        .flat()
        .reduce((a, b) => {
          a[b] = (a[b] || 0) + 1;
          return a;
        }, {});
      function roundedRectPath(x, y, width, height, bevel) {
        return (
          "M" +
          x +
          "," +
          y +
          `m 0 ${bevel[0]}` +
          `q 0 -${bevel[0]} ${bevel[0]} -${bevel[0]}` +
          `l ${width - bevel[0] - bevel[1]} 0` +
          `q ${bevel[1]} 0 ${bevel[1]} ${bevel[1]}` +
          `l 0 ${height - bevel[1] - bevel[2]}` +
          `q 0 ${bevel[2]} -${bevel[2]} ${bevel[2]}` +
          `l -${width - bevel[2] - bevel[3]} 0` +
          `q -${bevel[3]} 0 -${bevel[3]} -${bevel[3]}` +
          `z`
        );
      }
      xml =
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 " +
        this.size +
        " " +
        this.size +
        "'><rect x='0' y='0' width='" +
        this.size +
        "' height='" +
        this.size +
        "'  fill='" +
        bg +
        "'/><path fill='" +
        fg +
        "' d='";

      for (i = 0; i < this.rectangles.length; i++) {
        rect = this.rectangles[i];
        let bevel = rect.points.map((e) =>
          pointCounts[e] == 1 && this.getBit() ? this.cell / 2 : 0
        );
        xml += roundedRectPath(rect.x, rect.y, rect.w, rect.h, bevel) + " ";
      }
      xml += "'/></svg>";

      return xml;
    },

    getBase64: function () {
      return (
        "data:image/svg+xml;base64," +
        base64js.fromByteArray(new TextEncoder().encode(this.getDump()))
      );
    },
  };
  window.identicon = async data => (await new Identicon(data).render()).getBase64()
})();
