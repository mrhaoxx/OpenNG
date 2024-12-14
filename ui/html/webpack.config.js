import CssMinimizerPlugin from 'css-minimizer-webpack-plugin'
import HtmlWebPackPlugin from 'html-webpack-plugin'
import MiniCssExtractPlugin from 'mini-css-extract-plugin'
import HtmlInlineScriptPlugin from 'html-inline-script-webpack-plugin';

export default {
  output: {
    filename: '[contenthash].js',
    clean: true,
  },
  devtool: false,
  resolve: {
    extensions: ['.mjs', '.js', '.ts']
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader']
      },
      {
        test: /\.ts$/,
        loader: 'ts-loader',
        options: { transpileOnly: true }
      }
    ]
  },
  optimization: {
    minimize: true,
    minimizer: ['...', new CssMinimizerPlugin()],
    usedExports: true,
  },
  plugins: [new HtmlWebPackPlugin(
    {
      inject: 'body',
      minify: {
        collapseWhitespace: true,
        removeComments: true,
        removeRedundantAttributes: true,
        useShortDoctype: true,
      },
    }
  ), new MiniCssExtractPlugin({ filename: '[contenthash].css' })]
}

